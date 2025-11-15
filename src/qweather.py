from typing import Any, Optional
from cachetools import TTLCache
import httpx
from pydantic import BaseModel
import time
from threading import Thread
from prometheus_client import Gauge
from datetime import datetime, timedelta, timezone
import logging


class LocationConfig(BaseModel):
    name: str
    lon: float
    lat: float


class QWeatherConfig(BaseModel):
    api_key: str
    api_host: str
    interval_seconds: int = 10
    cache_ttl_seconds: int = 600
    locations: list[LocationConfig] = []


cfg: Optional[QWeatherConfig] = None

NAMESPACE = 'qweather'

obs_time_deplay_seconds = Gauge(
    namespace=NAMESPACE,
    name='obs_time_deplay_seconds',
    documentation='观测延时',
    labelnames=['location'],
)

temperature_celsius = Gauge(
    namespace=NAMESPACE,
    name='temperature_celsius',
    documentation='当前温度',
    labelnames=['location'],
)

humidity_percent = Gauge(
    namespace=NAMESPACE,
    name='humidity_percent',
    documentation='当前湿度',
    labelnames=['location'],
)

feels_like_celsius = Gauge(
    namespace=NAMESPACE,
    name='feels_like_celsius',
    documentation='体感温度',
    labelnames=['location'],
)

wind_360_degrees = Gauge(
    namespace=NAMESPACE,
    name='wind_360_degrees',
    documentation='风向（360度）',
    labelnames=['location'],
)

wind_scale_level = Gauge(
    namespace=NAMESPACE,
    name='wind_scale_level',
    documentation='风力等级',
    labelnames=['location'],
)

wind_speed_meters_per_second = Gauge(
    namespace=NAMESPACE,
    name='wind_speed_meters_per_second',
    documentation='风速',
    labelnames=['location'],
)

pressure_hpa = Gauge(
    namespace=NAMESPACE,
    name='pressure_hpa',
    documentation='气压',
    labelnames=['location'],
)


def init(_cfg: QWeatherConfig):
    global cfg
    cfg = _cfg
    print(f'初始化配置: {cfg}')
    if not cfg.api_key or not cfg.api_host:
        raise ValueError('请提供有效的 QWeather API Key 和 Host')
    print('QWeather 配置初始化完成')


weather_cache: Optional[TTLCache] = None


def get_weather_cache() -> TTLCache:
    global weather_cache
    if weather_cache is not None:
        return weather_cache
    if cfg is None:
        raise ValueError('请先调用 init() 初始化配置')
    weather_cache = TTLCache(
        maxsize=100,
        ttl=timedelta(seconds=cfg.cache_ttl_seconds).total_seconds(),
    )
    return weather_cache


def get_weather(lon: float, lat: float) -> Any:
    location = f"{format(lon, '.2f')},{format(lat, '.2f')}"
    weather_cache = get_weather_cache()
    if location in weather_cache:
        return weather_cache[location]
    logging.info(f'缓存过期，获取 {location} 的天气数据')
    url = httpx.URL(f'{cfg.api_host}/v7/grid-weather/now')
    resp = httpx.get(
        url=url,
        params={
            "location": location,
        },
        headers={
            'X-QW-Api-Key': cfg.api_key,
        })
    if resp.status_code != 200:
        raise httpx.HTTPStatusError(
            f'请求失败: {resp.status_code} - {resp.text}', request=resp.request, response=resp)
    ret = resp.json()
    weather_cache[location] = ret
    return ret


def collect_qweather(location_cfg: LocationConfig):
    resp_body = get_weather(location_cfg.lon, location_cfg.lat)
    logging.info(f'获取 {location_cfg.name} 的天气数据: {resp_body}')
    now_weather = resp_body['now']
    obs_time = datetime.fromisoformat(
        now_weather['obsTime']).astimezone(tz=timezone.utc)
    now_time = datetime.now(tz=timezone.utc)
    logging.info(f'观测时间: {obs_time}, 当前时间: {now_time}')
    obs_time_deplay_seconds.labels(location=location_cfg.name).set(
        value=(now_time - obs_time).total_seconds(),
    )
    temperature_celsius.labels(location=location_cfg.name).set(
        value=float(now_weather['temp']),
    )
    humidity_percent.labels(location=location_cfg.name).set(
        value=float(now_weather['humidity']),
    )
    feels_like_celsius.labels(location=location_cfg.name).set(
        value=float(now_weather['feelsLike']),
    )
    wind_360_degrees.labels(location=location_cfg.name).set(
        value=float(now_weather['wind360']),
    )
    wind_scale_level.labels(location=location_cfg.name).set(
        value=float(now_weather['windScale']),
    )
    wind_speed_meters_per_second.labels(location=location_cfg.name).set(
        value=float(now_weather['windSpeed']),
    )
    pressure_hpa.labels(location=location_cfg.name).set(
        value=float(now_weather['pressure']),
    )


def collect_once():
    try:
        for location in cfg.locations:
            collect_qweather(location)
    except Exception as e:
        logging.error(f'采集 QWeather 数据时发生错误: {e}')
        logging.exception(e)


def start_collect(config: Optional[QWeatherConfig] = None):
    """
    启动采集线程

    Args:
        config: QWeather配置，如果提供则在线程内初始化
    """
    def run():
        try:
            if config:
                init(config)

            if cfg is None:
                logging.error('QWeather配置未初始化')
                return

            while True:
                collect_once()
                time.sleep(cfg.interval_seconds)
        except Exception as e:
            logging.error(f"QWeather采集线程异常: {e}", exc_info=True)

    t = Thread(target=run, name='QWeatherCollectorThread', daemon=True)
    t.start()
    return t
