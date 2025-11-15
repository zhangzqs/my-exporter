import fnmatch
import logging
import os
from typing import Callable, Optional, Any
from mijiaAPI import mijiaAPI, mijiaLogin
import json
from pydantic import BaseModel
from threading import Thread
import time
from datetime import datetime
from prometheus_client import Gauge


class DeviceConfig(BaseModel):
    device_id: Optional[str]
    device_name: Optional[str]


class MiHomeConfig(BaseModel):
    auth_file: str = 'auth.json'
    devices_file: str = 'devices.json'
    devices: list[DeviceConfig] = []
    interval_seconds: float = 10.0
    device_name_alias: dict[str, str] = {}
    "根据device_id给设备起一个别名，用于在Prometheus中显示更友好的名称"


cfg: Optional[MiHomeConfig] = None
api: Optional[mijiaAPI] = None
devices: list[dict[str, Any]] = []


def init(_cfg: MiHomeConfig):
    global cfg, api, devices
    cfg = _cfg
    logging.info('初始化配置: %s', cfg)

    api = login_and_get_api()
    # 获取设备列表
    devices = api.get_devices_list()

    # 保存设备列表到文件
    with open(cfg.devices_file, 'w') as f:
        json.dump(devices, f, indent=4)
    logging.info(f'设备列表已保存到 {cfg.devices_file}')


def login_and_get_api():
    auther = mijiaLogin()
    try:
        with open(cfg.auth_file, 'r') as f:
            auth = json.load(f)
        auther.auth_data = auth
        logging.info('已成功加载认证信息: %s', cfg.auth_file)
    except FileNotFoundError:
        logging.info('未找到认证信息，尝试登录')
        auth = auther.QRlogin()
        with open(cfg.auth_file, 'w') as f:
            json.dump(auth, f, indent=4)
    except json.JSONDecodeError:
        logging.info('认证信息格式错误，尝试重新登录')
        os.remove(cfg.auth_file)
        return login_and_get_api()

    api = mijiaAPI(auth)
    if not api.available:
        logging.info('API 不可用，认证已过期，需要重新登录')
        os.remove(cfg.auth_file)
        return login_and_get_api()
    logging.info('登录成功')
    return api


def get_device_by_did(did: str):
    for device in devices:
        if device['did'] == did:
            return device
    raise ValueError(f'未找到did={did} 的设备')


def get_device_props(
    did: str,
    assert_model: str | None = None,
    sp_id_pairs: dict[str, (int, int)] = {},
) -> dict[str, dict[str, Any]]:
    device: dict = get_device_by_did(did)
    if assert_model:
        # 支持通配符匹配
        if '*' in assert_model:
            assert fnmatch.fnmatch(device['model'], assert_model), \
                f'设备 {device["name"]} 的型号 {device["model"]} 不符合通配模式 {assert_model}'
        else:
            assert device['model'] == assert_model, \
                f'设备 {device["name"]} 不是 {assert_model} 类型'

    query_list = []
    for _, (siid, piid) in sp_id_pairs.items():
        query_list.append({
            'did': device['did'],
            'siid': siid,
            'piid': piid,
        })
    logging.info(f'查询设备 {device["name"]} 的属性: {query_list}')
    props = api.get_devices_prop(query_list)
    logging.info(f'获取到设备 {device["name"]} 的属性: {props}')
    result = {}
    for prop in props:
        siid = prop['siid']
        piid = prop['piid']
        value = prop['value']
        update_time = datetime.fromtimestamp(float(prop['updateTime']))
        # 寻找sp_id_pairs中对应的键
        for key, (expected_siid, expected_piid) in sp_id_pairs.items():
            if siid == expected_siid and piid == expected_piid:
                now_time = datetime.now()
                result[key] = {
                    'value': value,
                    'delay_seconds': (now_time - update_time).total_seconds(),
                }
                break
    if 'localip' in device:
        result['device_ip'] = device['localip']
    return result


collectors: dict[str, Callable[[str], None]] = {}


def register_collector(**metadata):
    def decorator(func):
        for key, value in metadata.items():
            if not hasattr(func, key):
                collectors[value] = func
            else:
                logging.warning(
                    f'函数 {func.__name__} 已经有属性 {key}，将覆盖原有值')
            setattr(func, key, value)
        return func
    return decorator


NAMESPACE = 'mihome'
prop_delay_seconds = Gauge(
    namespace=NAMESPACE,
    name='prop_delay_seconds',
    documentation='属性更新延时',
    labelnames=['device_name', 'property_name', 'device_id'],
)

plug_power_on_status = Gauge(
    namespace=NAMESPACE,
    name='plug_power_on_status',
    documentation='插座电源状态',
    labelnames=['device_ip', 'device_name', 'device_id'],
)

plug_temperature = Gauge(
    namespace=NAMESPACE,
    name='plug_temperature',
    documentation='设备温度',
    labelnames=['device_ip', 'device_name', 'device_id'],
)

plug_electric_power = Gauge(
    namespace=NAMESPACE,
    name='plug_electric_power',
    documentation='功率',
    labelnames=['device_ip', 'device_name', 'device_id'],
)


@register_collector(model='cuco.plug.v3')
def collect_cuco_plug_v3_metrics(device_id: str):
    props = get_device_props(
        did=device_id,
        assert_model=collect_cuco_plug_v3_metrics.model,
        sp_id_pairs={
            'power_on_status': (2, 1),  # 电源状态
            'electric_power': (11, 2),  # 功率
            'temperature': (12, 2),  # 设备温度
        }
    )
    device = get_device_by_did(device_id)
    logging.info(f'采集 {device["name"]} 的数据: {props}')
    device_ip = props.get('device_ip', 'unknown')
    plug_power_on_status.labels(
        device_ip=device_ip,
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['power_on_status']['value'],
    )
    plug_electric_power.labels(
        device_ip=device_ip,
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['electric_power']['value'],
    )
    plug_temperature.labels(
        device_ip=device_ip,
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['temperature']['value'],
    )
    for property_name in ['power_on_status', 'electric_power', 'temperature']:
        prop_delay_seconds.labels(
            device_name=device['name'],
            device_id=device_id,
            property_name=property_name,
        ).set(
            value=props[property_name]['delay_seconds'],
        )


@register_collector(model='chuangmi.plug.m3')
def collect_chuangmi_plug_m3_metrics(device_id: str):
    props = get_device_props(
        did=device_id,
        assert_model=collect_chuangmi_plug_m3_metrics.model,
        sp_id_pairs={
            'power_on_status': (2, 1),  # 电源状态
            'temperature': (2, 2),  # 设备温度
        }
    )
    device = get_device_by_did(device_id)
    logging.info(f'采集 {device["name"]} 的数据: {props}')
    device_ip = props.get('device_ip', 'unknown')
    plug_power_on_status.labels(
        device_ip=device_ip,
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['power_on_status']['value'],
    )
    plug_temperature.labels(
        device_ip=device_ip,
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['temperature']['value'],
    )
    for property_name in ['power_on_status', 'temperature']:
        prop_delay_seconds.labels(
            device_name=device['name'],
            device_id=device_id,
            property_name=property_name,
        ).set(
            value=props[property_name]['delay_seconds'],
        )


sensor_ht_temperature = Gauge(
    namespace=NAMESPACE,
    name='sensor_ht_temperature',
    documentation='温度',
    labelnames=['device_name', 'device_id'],
)

sensor_ht_relative_humidity = Gauge(
    namespace=NAMESPACE,
    name='sensor_ht_relative_humidity',
    documentation='相对湿度',
    labelnames=['device_name', 'device_id'],
)

sensor_ht_battery_level = Gauge(
    namespace=NAMESPACE,
    name='sensor_ht_battery_level',
    documentation='电池电量',
    labelnames=['device_name', 'device_id'],
)


@register_collector(model='miaomiaoce.sensor_ht.t2')
def collect_miaomiaoce_sensor_ht_t2(device_id: str):
    props = get_device_props(
        did=device_id,
        assert_model=collect_miaomiaoce_sensor_ht_t2.model,
        sp_id_pairs={
            'temperature': (2, 1),  # 温度
            'relative_humidity': (2, 2),  # 相对湿度
            'battery_level': (3, 1),  # 电池电量
        }
    )
    device = get_device_by_did(device_id)
    logging.info(f'采集 {device["name"]} 的数据: {props}')
    sensor_ht_temperature.labels(
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['temperature']['value'],
    )
    sensor_ht_relative_humidity.labels(
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['relative_humidity']['value'],
    )
    sensor_ht_battery_level.labels(
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['battery_level']['value'],
    )
    for property_name in ['temperature', 'relative_humidity', 'battery_level']:
        prop_delay_seconds.labels(
            device_name=device['name'],
            device_id=device_id,
            property_name=property_name,
        ).set(
            value=props[property_name]['delay_seconds'],
        )


router_download_speed = Gauge(
    namespace=NAMESPACE,
    name='router_download_speed',
    documentation='路由器下载速度',
    labelnames=['device_name', 'device_id'],
)

router_connected_device_number = Gauge(
    namespace=NAMESPACE,
    name='router_connected_device_number',
    documentation='路由器连接的设备数量',
    labelnames=['device_name', 'device_id'],
)


@register_collector(model='xiaomi.router.*')
def collect_router_metrics(device_id: str):
    props = get_device_props(
        did=device_id,
        assert_model=collect_router_metrics.model,
        sp_id_pairs={
            'download_speed': (2, 1),  # 下载速度
            'connected_device_number': (2, 2),  # 连接的设备数量
        }
    )
    device = get_device_by_did(device_id)
    logging.info(f'采集 {device["name"]} 的数据: {props}')
    router_download_speed.labels(
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['download_speed']['value'],
    )
    router_connected_device_number.labels(
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['connected_device_number']['value'],
    )
    for property_name in ['download_speed', 'connected_device_number']:
        prop_delay_seconds.labels(
            device_name=device['name'],
            device_id=device_id,
            property_name=property_name,
        ).set(
            value=props[property_name]['delay_seconds'],
        )


cooker_status = Gauge(
    namespace=NAMESPACE,
    name='cooker_status',
    documentation='电饭煲烹饪状态',
    labelnames=['device_name', 'device_id'],
)


@register_collector(model='chunmi.cooker.normal2')
def collect_cooker_metrics(device_id: str):
    props = get_device_props(
        did=device_id,
        assert_model=collect_cooker_metrics.model,
        sp_id_pairs={
            'cooker_status': (2, 1),  # 烹饪状态
        }
    )
    device = get_device_by_did(device_id)
    logging.info(f'采集 {device["name"]} 的数据: {props}')
    cooker_status.labels(
        device_name=device['name'],
        device_id=device_id,
    ).set(
        value=props['cooker_status']['value'],
    )
    for property_name in ['cooker_status']:
        prop_delay_seconds.labels(
            device_name=device['name'],
            device_id=device_id,
            property_name=property_name,
        ).set(
            value=props[property_name]['delay_seconds'],
        )


@register_collector(model='lumi.acpartner.mcn02')
def collect_lumi_acpartner_mcn02_metrics(device_id: str):
    "米家空调伴侣2设备数据采集"
    props = get_device_props(
        did=device_id,
        assert_model=collect_lumi_acpartner_mcn02_metrics.model,
        sp_id_pairs={
            'power_on_status': (2, 1),
            'electric_power': (5, 1),
        }
    )
    device = get_device_by_did(device_id)
    logging.info(f'采集 {device["name"]} 的数据: {props}')
    device_ip = device.get('localip', 'unknown')
    labels = {
        'device_ip': device_ip,
        'device_name': device['name'],
        'device_id': device_id,
    }
    plug_power_on_status.labels(**labels).set(
        value=props['power_on_status']['value'],
    )
    plug_electric_power.labels(**labels).set(
        value=props['electric_power']['value'],
    )

    for property_name in ['power_on_status', 'electric_power']:
        prop_delay_seconds.labels(
            device_name=device['name'],
            device_id=device_id,
            property_name=property_name,
        ).set(
            value=props[property_name]['delay_seconds'],
        )


def collector_by_id(device_id: str):
    device = get_device_by_did(device_id)
    matcherd_collector: Optional[Callable[[str], None]] = None
    for (model_matcher, collector) in collectors.items():
        if '*' in model_matcher:
            if fnmatch.fnmatch(device['model'], model_matcher):
                if matcherd_collector is None:
                    matcherd_collector = collector
                else:
                    logging.warning(
                        f'设备 {device_id} 匹配到多个收集器: {matcherd_collector.__name__} 和 {collector.__name__}')
        else:
            if device['model'] == model_matcher:
                matcherd_collector = collector
    if matcherd_collector is None:
        logging.warning(
            f'未找到设备 {device_id} 的收集器，请检查设备型号和注册的收集器')
        return
    logging.info(f'使用收集器 {matcherd_collector.__name__} 采集设备 {device_id} 的数据')
    matcherd_collector(device_id)


def model_in_collector(model: str) -> bool:
    for (model_matcher, _) in collectors.items():
        if '*' in model_matcher:
            if fnmatch.fnmatch(model, model_matcher):
                return True
        else:
            if model == model_matcher:
                return True
    return False


def get_need_collect_device_id_list() -> list[str]:
    if cfg.devices is None or len(cfg.devices) == 0:
        return list(map(lambda x: x['did'], filter(lambda x: model_in_collector(x['model']), devices)))
    ret = []
    for device_cfg in cfg.devices:
        # 判断device_name是否在devices中
        if device_cfg.device_id is not None and any(map(lambda x: x['did'] == device_cfg.device_id, devices)):
            ret.append(device_cfg.device_id)
    return ret


def collect_once():
    try:
        for device_id in get_need_collect_device_id_list():
            collector_by_id(device_id)
    except Exception as e:
        logging.error(f'采集数据时发生错误: {e}')
        logging.exception(e)


def start_collect(config: Optional[MiHomeConfig] = None) -> Thread:
    """
    启动采集线程
    
    Args:
        config: MiHome配置，如果提供则在线程内初始化
    """
    def run():
        global cfg, devices
        try:
            if config:
                init(config)
            
            if cfg is None:
                logging.error('MiHome配置未初始化')
                return
            
            # 设置设备别名
            for (did, alias_name) in cfg.device_name_alias.items():
                for device in devices:
                    if device['did'] == did:
                        device['name'] = alias_name
                        break
                else:
                    logging.warning(f'未找到设备 {did}，无法设置设备别名 {alias_name}')
                    continue
            
            while True:
                collect_once()
                time.sleep(cfg.interval_seconds)
        except Exception as e:
            logging.error(f"MiHome采集线程异常: {e}", exc_info=True)

    t = Thread(target=run, name='MiHomeCollectorThread', daemon=True)
    t.start()
    return t
