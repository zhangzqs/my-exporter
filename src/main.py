from threading import Thread
from typing import Optional
import prometheus_client as pc
from config import load_config_from_args
from logger import LoggerConfig, init_logger
from pydantic import BaseModel
import logging
import mihome
import qweather
import mirouter
import sslcert


class Config(BaseModel):
    logger: LoggerConfig
    port: int = 8000
    mihome_config: Optional[mihome.MiHomeConfig] = None
    qweather_config: Optional[qweather.QWeatherConfig] = None
    mirouter_config: Optional[mirouter.MiRouterConfig] = None
    sslcert_config: Optional[sslcert.SSLCertConfig] = None


def main():
    cfg = load_config_from_args(Config)
    init_logger(cfg.logger, logging.getLogger())
    pc.start_http_server(port=cfg.port)
    logging.info(f"Starting MiHome Exporter on port {cfg.port}")

    threads: list[Thread] = []

    # MiHome collector
    if cfg.mihome_config:
        threads.append(mihome.start_collect(cfg.mihome_config))
        logging.info("MiHome collector thread started.")
    else:
        logging.warning(
            "MiHome configuration is not provided, skipping MiHome collector initialization."
        )

    # QWeather collector
    if cfg.qweather_config:
        threads.append(qweather.start_collect(cfg.qweather_config))
        logging.info("QWeather collector thread started.")
    else:
        logging.warning(
            "QWeather configuration is not provided, skipping QWeather collector initialization."
        )

    # MiRouter collector
    if cfg.mirouter_config:
        threads.append(mirouter.start_collect(cfg.mirouter_config))
        logging.info("MiRouter collector thread started.")
    else:
        logging.warning(
            "MiRouter configuration is not provided, skipping MiRouter collector initialization."
        )

    # SSLCert collector
    if cfg.sslcert_config:
        threads.append(sslcert.start_collect(cfg.sslcert_config))
        logging.info("SSLCert collector thread started.")
    else:
        logging.warning(
            "SSLCert configuration is not provided, skipping SSLCert collector initialization."
        )

    if not threads:
        logging.error(
            "No collectors started, exiting. Please provide valid configurations."
        )
        return

    logging.info(
        f"Successfully started {len(threads)} collector(s). Monitoring...")

    while True:
        for thread in threads:
            if not thread.is_alive():
                logging.error(
                    f"Thread {thread.name} has stopped unexpectedly. Exiting."
                )
                return
        for thread in threads:
            thread.join(timeout=1)


if __name__ == "__main__":
    main()
