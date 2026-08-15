"""
log_store.py — Plain text rotating debug logs.
Logs go to storage/logs/enclave.log with daily rotation (max 5 backups).
"""

import os
import logging
from logging.handlers import TimedRotatingFileHandler


_logger_registry: dict[str, logging.Logger] = {}
_root_handlers: list = []  # handlers we've attached to root, so we can swap them


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

        # This logger's own messages already go through the handlers
        # above; don't ALSO let them propagate to root and get handled a
        # second time by the root handlers below.
        logger.propagate = False

        # core/network/router.py, discovery.py, and transport.py (and
        # potentially other modules) each grab their own
        # logging.getLogger("network")-style logger directly, entirely
        # independent of this function. Without root configured at all,
        # those loggers get no handler, default to WARNING via root's
        # default level, and only escape through Python's
        # logging.lastResort fallback (WARNING+ to stderr) — every
        # INFO/DEBUG call from those modules is silently dropped.
        # Confirmed concretely: two real profiles running discovery
        # against each other correctly populated peer_store with each
        # other's full, correct data (the mechanism works), while
        # discovery.py's log.info("saw peer") never appeared anywhere.
        #
        # This has to REPLACE root's handlers on every call, not just set
        # them once: main.py unconditionally calls _init_stores() at
        # import time for the default profile, before cmd_run's own
        # _init_stores(args.profile) call for the profile actually
        # selected on the command line. A "configure root once" flag
        # would leave root permanently pointed at the DEFAULT profile's
        # log file for the rest of the process, no matter which profile
        # ends up active — confirmed this exact failure mode too: with a
        # one-shot flag, "saw peer" reliably went missing specifically
        # for non-default profiles. Swapping root's handlers to the most
        # recently constructed logger means the LAST get_logger() call
        # before the app actually starts running — which in the real CLI
        # flow is always the truly active profile — wins.
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        for h in _root_handlers:
            root.removeHandler(h)
        _root_handlers.clear()
        root.addHandler(handler)
        root.addHandler(console)
        _root_handlers.extend([handler, console])

    _logger_registry[name] = logger
    return logger


class LogStore:
    """Thin wrapper around get_logger for consistent usage across the project."""

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
