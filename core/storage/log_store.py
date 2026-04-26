"""
log_store.py — Plain text rotating debug logs.
Logs go to storage/logs/enclave.log with daily rotation (max 5 backups).
"""

import os
import logging
from logging.handlers import TimedRotatingFileHandler


_logger_registry: dict[str, logging.Logger] = {}


def get_logger(name: str = "enclave", base_dir: str = "storage") -> logging.Logger:
    """
    Returns a named logger that writes to storage/logs/<name>.log
    with daily rotation and 5 backup files.
    """
    if name in _logger_registry:
        return _logger_registry[name]

    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    log_file = os.path.join(logs_dir, f"{name}.log")

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        handler = TimedRotatingFileHandler(
            log_file,
            when="midnight",
            backupCount=5,
            encoding="utf-8",
        )
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(formatter)
        logger.addHandler(console)

    _logger_registry[name] = logger
    return logger


class LogStore:
    """Thin wrapper around get_logger for consistent usage across the app."""

    def __init__(self, name: str = "enclave", base_dir: str = "storage"):
        self.logger = get_logger(name=name, base_dir=base_dir)

    def debug(self, msg: str):
        self.logger.debug(msg)

    def info(self, msg: str):
        self.logger.info(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)

    def critical(self, msg: str):
        self.logger.critical(msg)
