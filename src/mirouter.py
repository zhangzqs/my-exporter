import logging
from threading import Thread
from typing import List, Optional, Type, TypeVar, Union
import httpx
from pydantic import BaseModel, field_validator
import time
import random
import hashlib
from prometheus_client import Gauge
from functools import lru_cache


def hashPassword(pwd: str, nonce: str) -> str:
    key = "a2ffa5c9be07488bbb04a3a47d3c5f6a"
    pwd_key = pwd + key
    pwdKeyHash = hashlib.sha1(pwd_key.encode()).hexdigest()

    nonce_pwd_key = nonce + pwdKeyHash
    noncePwdKeyHash = hashlib.sha1(nonce_pwd_key.encode()).hexdigest()
    return noncePwdKeyHash


def createNonce() -> str:
    typeVar = 0
    deviceID = ""
    timeVar = int(time.time())  # 获取当前Unix时间戳
    randomVar = random.randint(0, 9999)  # 生成0-9999的随机整数
    return f"{typeVar}_{deviceID}_{timeVar}_{randomVar}"


class MiRouterConfig(BaseModel):
    base_addr: str = "http://miwifi.com"
    "路由器地址"
    password: str
    "路由器密码"
    interval_seconds: int = 10
    "采集间隔，单位是秒"
    device_name_alias_by_mac: dict[str, str] = {}
    "设备名称别名，key是mac地址，value是设备名称"


cfg: Optional[MiRouterConfig] = None


def init(_cfg: MiRouterConfig):
    global cfg
    cfg = _cfg


class InitInfo(BaseModel):
    romversion: str
    countrycode: str
    id: str
    routername: str
    "路由器名称"

    routerId: str
    hardware: str
    "路由器型号"

    newEncryptMode: Optional[float] = None
    "如果不为None则使用新的加密模式"


T = TypeVar("T", bound=BaseModel)


def must_get_body(resp: httpx.Response, t: Type[T]) -> T:
    resp.raise_for_status()
    resp_body = resp.json()
    logging.info(f"response body: {resp_body}")
    if resp_body.get('code') != 0:
        raise RuntimeError(f"请求失败：{resp_body}")
    return t(**resp_body)


def get_init_info() -> InitInfo:
    resp = httpx.get(
        url=f"{cfg.base_addr}/cgi-bin/luci/api/xqsystem/init_info",
    )
    return must_get_body(resp, InitInfo)


class LoginResponse(BaseModel):
    token: str


@lru_cache(maxsize=1)
def login() -> LoginResponse:
    init_into = get_init_info()
    nonce = createNonce()
    if init_into.newEncryptMode is None:
        hashed_password = hashPassword(cfg.password, nonce)
    else:
        raise NotImplementedError(
            "小米路由器新的加密模式尚未实现，不支持登录"
        )
    resp = httpx.post(
        url=f"{cfg.base_addr}/cgi-bin/luci/api/xqsystem/login",
        data={
            "username": "admin",
            "password": hashed_password,
            "logtype": "2",
            "nonce": nonce,
        },
    )
    return must_get_body(resp, LoginResponse)


NAMESPACE = "mirouter"

device_status_labels = ['device_name', 'mac', 'known']

device_status_up_bytes = Gauge(
    namespace=NAMESPACE,
    name='device_status_up_bytes',
    documentation='设备上传字节数',
    labelnames=device_status_labels,
)

device_status_down_bytes = Gauge(
    namespace=NAMESPACE,
    name='device_status_down_bytes',
    documentation='设备下载字节数',
    labelnames=device_status_labels,
)

device_status_up_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='device_status_up_bytes_per_second',
    documentation='设备上传速度（字节/秒）',
    labelnames=device_status_labels,
)

device_status_down_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='device_status_down_bytes_per_second',
    documentation='设备下载速度（字节/秒）',
    labelnames=device_status_labels,
)

device_status_online_seconds = Gauge(
    namespace=NAMESPACE,
    name='device_status_online_seconds',
    documentation='设备在线时长（秒）',
    labelnames=device_status_labels,
)

device_status_max_up_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='device_status_max_up_bytes_per_second',
    documentation='设备最大上传速度（字节/秒）',
    labelnames=device_status_labels,
)

device_status_max_down_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='device_status_max_down_bytes_per_second',
    documentation='设备最大下载速度（字节/秒）',
    labelnames=device_status_labels,
)


class DeviceStatus(BaseModel):
    devname: str
    "设备名称"
    mac: str
    "mac地址"
    upspeed: Union[str, int]
    "实时上传速度"
    downspeed: Union[str, int]
    "实时下载速度"
    upload: Union[str, int]
    "当前已上传量"
    download: Union[str, int]
    "当前已下载量"
    online: Union[str, int]
    "在线了多久，单位是秒"
    maxdownloadspeed: Union[str, int]
    "最大下载速度"
    maxuploadspeed: Union[str, int]
    "最大上传速度"


def collect_device_status(s: DeviceStatus):
    for mac, devname in cfg.device_name_alias_by_mac.items():
        if s.mac.lower() == mac.lower():
            s.devname = devname
            known = "true"
            logging.info(
                f"设备 {s.mac} 的别名已设置为 {s.devname}，并标记为已知设备"
            )
            break
    else:
        if s.mac == "":  # 这是其他剩余设备的状态
            s.devname = "其他设备"
            known = "true"
        else:
            known = "false"
            logging.warning(
                f"未找到设备 {s.mac} 的别名，作为未知设备，将使用默认名称 {s.devname}。建议在配置中添加别名。"
            )

    labels = {
        'device_name': s.devname,
        'mac': s.mac,
        'known': known,
    }
    device_status_up_bytes.labels(
        **labels
    ).set(int(s.upload))
    device_status_down_bytes.labels(
        **labels
    ).set(int(s.download))
    device_status_up_bytes_per_second.labels(
        **labels
    ).set(int(s.upspeed))
    device_status_down_bytes_per_second.labels(
        **labels
    ).set(int(s.downspeed))
    device_status_online_seconds.labels(
        **labels
    ).set(int(s.online))
    device_status_max_up_bytes_per_second.labels(
        **labels
    ).set(int(s.maxuploadspeed))
    device_status_max_down_bytes_per_second.labels(
        **labels
    ).set(int(s.maxdownloadspeed))


class MemoryStatus(BaseModel):
    usage: float
    "内存使用率"


memory_usage_percent = Gauge(
    namespace=NAMESPACE,
    name='memory_usage_percent',
    documentation='内存使用率',
)


def collect_memory_status(s: MemoryStatus):
    memory_usage_percent.set(s.usage)


class CountStatus(BaseModel):
    all: int
    "历史累计在线设备数"
    online: int
    "当前在线设备数"


history_device_count = Gauge(
    namespace=NAMESPACE,
    name='history_device_count',
    documentation='历史累计在线设备数',
)

current_online_device_count = Gauge(
    namespace=NAMESPACE,
    name='current_online_device_count',
    documentation='当前在线设备数',
)


def collect_count_status(s: CountStatus):
    history_device_count.set(s.all)
    current_online_device_count.set(s.online)


class CpuStatus(BaseModel):
    load: float
    "CPU使用率"


cpu_load_percent = Gauge(
    namespace=NAMESPACE,
    name='cpu_load_percent',
    documentation='CPU使用率',
)


def collect_cpu_status(s: CpuStatus):
    cpu_load_percent.set(s.load)


class WanStatus(BaseModel):
    devname: str
    "设备名称"
    upspeed: Union[str, int]
    "实时上传速度"
    downspeed: Union[str, int]
    "实时下载速度"
    upload: Union[str, int]
    "当前已上传量"
    download: Union[str, int]
    "当前已下载量"
    maxdownloadspeed: Union[str, int]
    "最大下载速度"
    maxuploadspeed: Union[str, int]
    "最大上传速度"


wan_up_bytes = Gauge(
    namespace=NAMESPACE,
    name='wan_up_bytes',
    documentation='WAN口上传字节数',
    labelnames=['device_name'],
)

wan_down_bytes = Gauge(
    namespace=NAMESPACE,
    name='wan_down_bytes',
    documentation='WAN口下载字节数',
    labelnames=['device_name'],
)

wan_up_speed_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='wan_up_speed_bytes_per_second',
    documentation='WAN口上传速度（字节/秒）',
    labelnames=['device_name'],
)

wan_down_speed_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='wan_down_speed_bytes_per_second',
    documentation='WAN口下载速度（字节/秒）',
    labelnames=['device_name'],
)

wan_max_up_speed_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='wan_max_up_speed_bytes_per_second',
    documentation='WAN口最大上传速度（字节/秒）',
    labelnames=['device_name'],
)

wan_max_down_speed_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='wan_max_down_speed_bytes_per_second',
    documentation='WAN口最大下载速度（字节/秒）',
    labelnames=['device_name'],
)


def collect_wan_status(s: WanStatus):
    wan_up_bytes.labels(
        device_name=s.devname
    ).set(int(s.upload))
    wan_down_bytes.labels(
        device_name=s.devname
    ).set(int(s.download))
    wan_up_speed_bytes_per_second.labels(
        device_name=s.devname
    ).set(int(s.upspeed))
    wan_down_speed_bytes_per_second.labels(
        device_name=s.devname
    ).set(int(s.downspeed))
    wan_max_up_speed_bytes_per_second.labels(
        device_name=s.devname
    ).set(int(s.maxuploadspeed))
    wan_max_down_speed_bytes_per_second.labels(
        device_name=s.devname
    ).set(int(s.maxdownloadspeed))


class StatusResponse(BaseModel):
    dev: list[DeviceStatus]
    "设备状态列表"
    mem: MemoryStatus
    "内存状态"
    count: CountStatus
    "设备统计信息"
    upTime: str
    "路由器运行时间，单位是秒"
    cpu: CpuStatus
    "CPU状态"
    wan: WanStatus
    "WAN口状态"


up_time_seconds = Gauge(
    namespace=NAMESPACE,
    name='up_time_seconds',
    documentation='路由器运行时间（秒）',
)


def collect_status(s: StatusResponse):
    for device_status in s.dev:
        collect_device_status(device_status)
    collect_memory_status(s.mem)
    collect_count_status(s.count)
    collect_cpu_status(s.cpu)
    collect_wan_status(s.wan)
    up_time_seconds.set(float(s.upTime))


def get_status() -> StatusResponse:
    token = login().token
    resp = httpx.get(
        url=f"{cfg.base_addr}/cgi-bin/luci/;stok={token}/api/misystem/status",
    )
    return must_get_body(resp, StatusResponse)


class Authority(BaseModel):
    wan: int
    pridisk: int
    admin: int
    lan: int


class IPDetail(BaseModel):
    downspeed: str
    online: str
    active: int
    upspeed: str
    ip: str


class Statistics(BaseModel):
    downspeed: str
    online: str
    upspeed: str


class Device(BaseModel):
    mac: str
    oname: str
    isap: int
    parent: str
    authority: Authority
    push: int
    online: int
    name: str
    times: int
    ip: List[IPDetail]
    statistics: Optional[Statistics] = None
    icon: str
    type: int

    @field_validator('statistics', mode='before')
    @classmethod
    def validate_statistics(cls, v):
        # 处理空列表的情况
        if isinstance(v, list) and len(v) == 0:
            return None
        return v


class DeviceListResponse(BaseModel):
    mac: str
    list: List[Device]
    code: int


def get_device_list() -> DeviceListResponse:
    token = login().token
    resp = httpx.get(
        url=f"{cfg.base_addr}/cgi-bin/luci/;stok={token}/api/misystem/devicelist",
    )
    print(f"获取设备列表响应: {resp.text}")
    return must_get_body(resp, DeviceListResponse)


device_list_labels = ['device_name', 'mac', 'known', 'device_ip']

device_list_up_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='device_list_up_bytes_per_second',
    documentation='设备上传速度（字节/秒）',
    labelnames=device_list_labels,
)

device_list_down_bytes_per_second = Gauge(
    namespace=NAMESPACE,
    name='device_list_down_bytes_per_second',
    documentation='设备下载速度（字节/秒）',
    labelnames=device_list_labels,
)

device_list_online_seconds = Gauge(
    namespace=NAMESPACE,
    name='device_list_online_seconds',
    documentation='设备在线时长（秒）',
    labelnames=device_list_labels,
)

device_list_unknown_count = Gauge(
    namespace=NAMESPACE,
    name='device_list_unknown_count',
    documentation='未知设备数量',
    labelnames=['device_name', 'mac'],
)


def collect_device_list(devicelist: DeviceListResponse):
    for device in devicelist.list:
        for mac, devname in cfg.device_name_alias_by_mac.items():
            if device.mac.lower() == mac.lower():
                device.name = devname
                known = "true"
                logging.info(
                    f"设备 {device.mac} 的别名已设置为 {device.name}，并标记为已知设备"
                )
                break
        else:
            known = "false"
            device_list_unknown_count.labels(
                device_name=device.name,
                mac=device.mac,
            ).set(1)
            logging.warning(
                f"未找到设备 {device.mac} 的别名，作为未知设备，将使用默认名称 {device.name}。建议在配置中添加别名。"
            )
        for ip_detail in device.ip:
            labels = {
                'device_name': device.name,
                'mac': device.mac,
                'known': known,
                'device_ip': ip_detail.ip,
            }
            device_list_up_bytes_per_second.labels(
                **labels
            ).set(int(ip_detail.upspeed))
            device_list_down_bytes_per_second.labels(
                **labels
            ).set(int(ip_detail.downspeed))
            device_list_online_seconds.labels(
                **labels
            ).set(int(ip_detail.online))


def collect_once():
    while True:
        try:
            # 收集路由器状态
            status = get_status()
            logging.debug("成功获取路由器状态: %s", status.model_dump_json())
            logging.info("当前在线设备数量: %d", status.count.online)
            collect_status(status)
            logging.info("路由器状态已收集")

            # 收集设备列表
            devicelist = get_device_list()
            logging.debug("成功获取设备列表: %s", devicelist.model_dump_json())
            collect_device_list(devicelist)
            logging.info("设备列表已收集")
            return
        except Exception as e:
            logging.error(f"获取状态时发生错误: {e}")
            logging.exception(e)
            login.cache_clear()  # 清空缓存后重试
            logging.warn("正在重试获取路由器状态...")


def start_collect(config: Optional[MiRouterConfig] = None) -> Thread:
    """
    启动采集线程

    Args:
        config: MiRouter配置，如果提供则在线程内初始化
    """
    def run():
        try:
            if config:
                init(config)

            if cfg is None:
                logging.error('MiRouter配置未初始化')
                return

            while True:
                collect_once()
                time.sleep(cfg.interval_seconds)
        except Exception as e:
            logging.error(f"MiRouter采集线程异常: {e}", exc_info=True)

    t = Thread(target=run, name='MiRouterCollectorThread', daemon=True)
    t.start()
    return t
