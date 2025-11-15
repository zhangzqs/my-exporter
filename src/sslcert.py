import ssl
import socket
import logging
from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from threading import Thread
import time
from prometheus_client import Gauge


class DomainConfig(BaseModel):
    domain: str
    port: int = 443
    timeout: int = 10
    remark: Optional[str] = None


class SSLCertConfig(BaseModel):
    interval_seconds: float = 3600.0  # 默认每小时检查一次
    domains: list[DomainConfig] = Field(default_factory=list)


cfg: Optional[SSLCertConfig] = None

NAMESPACE = 'sslcert'

# 证书是否有效 (1=有效, 0=无效)
cert_valid = Gauge(
    namespace=NAMESPACE,
    name='valid',
    documentation='SSL证书是否有效 (1=有效, 0=无效)',
    labelnames=['domain', 'port', 'issuer', 'subject', 'remark'],
)

# 证书剩余有效秒数
cert_remaining_seconds = Gauge(
    namespace=NAMESPACE,
    name='remaining_seconds',
    documentation='SSL证书剩余有效秒数',
    labelnames=['domain', 'port', 'issuer', 'subject', 'remark'],
)

# 连接错误指标 (1=有错误, 0=正常)
cert_connection_error = Gauge(
    namespace=NAMESPACE,
    name='connection_error',
    documentation='连接或获取证书时是否出错 (1=有错误, 0=正常)',
    labelnames=['domain', 'port', 'error_type', 'remark'],
)


def init(_cfg: SSLCertConfig):
    global cfg
    cfg = _cfg
    logging.info(f'初始化SSL证书监控配置: {cfg}')


def get_ssl_cert_info(domain: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """
    获取指定域名的SSL证书信息

    Args:
        domain: 域名
        port: 端口，默认443
        timeout: 超时时间(秒)

    Returns:
        证书信息字典，失败返回None
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except socket.timeout:
        logging.error(f"连接 {domain}:{port} 超时")
        return None
    except socket.gaierror as e:
        logging.error(f"无法解析域名 {domain}: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL错误 {domain}:{port}: {e}")
        return None
    except Exception as e:
        logging.error(f"获取 {domain}:{port} 证书信息时发生未知错误: {e}")
        return None


def parse_cert_datetime(date_str: str) -> datetime:
    """
    解析证书日期字符串
    格式: 'Jan  1 00:00:00 2025 GMT'
    """
    return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)


def collect_cert_metrics(domain_cfg: DomainConfig):
    """
    采集单个域名的SSL证书指标
    """
    domain = domain_cfg.domain
    port = domain_cfg.port
    timeout = domain_cfg.timeout
    remark = domain_cfg.remark or ''

    logging.info(f"开始检查 {domain}:{port} 的SSL证书")

    now = datetime.now(timezone.utc)

    cert_info = get_ssl_cert_info(domain, port, timeout)

    if cert_info is None:
        # 连接失败，设置错误指标
        cert_connection_error.labels(
            domain=domain, port=port, error_type='connection_failed', remark=remark).set(1)
        unknown_labels = dict(domain=domain, port=port,
                              issuer='unknown', subject='unknown', remark=remark)
        cert_valid.labels(**unknown_labels).set(0)
        cert_remaining_seconds.labels(**unknown_labels).set(0)
        logging.warning(f"无法获取 {domain}:{port} 的证书信息")
        return

    # 连接成功，清除错误指标
    cert_connection_error.labels(
        domain=domain, port=port, error_type='connection_failed', remark=remark).set(0)

    try:
        # 解析证书时间
        not_before = parse_cert_datetime(cert_info['notBefore'])
        not_after = parse_cert_datetime(cert_info['notAfter'])

        # 提取证书信息
        subject = dict(x[0] for x in cert_info.get('subject', ()))
        issuer = dict(x[0] for x in cert_info.get('issuer', ()))

        subject_cn = subject.get('commonName', 'unknown')
        issuer_cn = issuer.get('commonName', 'unknown')

        # 计算剩余秒数并确保非负
        remaining_seconds = max((not_after - now).total_seconds(), 0.0)

        # 判断证书是否有效
        is_valid = not_before <= now <= not_after

        # 更新指标
        labels = dict(
            domain=domain,
            port=port,
            issuer=issuer_cn,
            subject=subject_cn,
            remark=remark,
        )
        cert_valid.labels(**labels).set(1 if is_valid else 0)
        cert_remaining_seconds.labels(**labels).set(remaining_seconds)
        cert_connection_error.labels(
            domain=domain, port=port, error_type='parse_error', remark=remark).set(0)

        logging.info(
            f"{domain}:{port} 证书信息: "
            f"主题={subject_cn}, 颁发者={issuer_cn}, "
            f"剩余秒数={remaining_seconds:.0f}, 有效={is_valid}, "
            f"生效时间={not_before.isoformat()}, 过期时间={not_after.isoformat()}"
        )

    except Exception as e:
        logging.error(f"解析 {domain}:{port} 证书信息时出错: {e}")
        cert_connection_error.labels(
            domain=domain, port=port, error_type='parse_error', remark=remark).set(1)
        unknown_labels = dict(domain=domain, port=port,
                              issuer='unknown', subject='unknown', remark=remark)
        cert_valid.labels(**unknown_labels).set(0)
        cert_remaining_seconds.labels(**unknown_labels).set(0)


def collect_all_metrics():
    """
    采集所有配置域名的SSL证书指标
    """
    if not cfg or not cfg.domains:
        logging.warning("没有配置需要监控的域名")
        return

    for domain_cfg in cfg.domains:
        try:
            collect_cert_metrics(domain_cfg)
        except Exception as e:
            logging.error(
                f"采集 {domain_cfg.domain}:{domain_cfg.port} 指标时发生异常: {e}")


def collect_loop():
    """
    定期采集指标的循环
    """
    if not cfg:
        logging.error("SSL证书监控未初始化配置，采集线程退出")
        return

    logging.info(f"SSL证书监控线程启动，采集间隔: {cfg.interval_seconds}秒")

    while True:
        try:
            collect_all_metrics()
        except Exception as e:
            logging.error(f"SSL证书采集循环中发生异常: {e}")

        time.sleep(cfg.interval_seconds)


def start_collect(config: Optional[SSLCertConfig] = None) -> Thread:
    """
    启动采集线程

    Args:
        config: SSL证书配置，如果提供则在线程内初始化
    """
    def run():
        try:
            if config:
                init(config)
            collect_loop()
        except Exception as e:
            logging.error(f"SSL证书采集线程异常: {e}", exc_info=True)

    thread = Thread(target=run, name='SSLCertCollector', daemon=True)
    thread.start()
    return thread
