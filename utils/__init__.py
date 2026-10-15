"""Utils package initialization"""

from .config import WAFConfig, get_config, reload_config
from .forensic_logging import ForensicLogger


class WAFLogger:
    """Simple structured logger wrapper"""

    def __init__(self, name: str):
        import logging
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
            )
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

    def _fmt(self, msg, **kwargs):
        if kwargs:
            kv = " ".join(f"{k}={v}" for k, v in kwargs.items())
            return f"{msg} | {kv}"
        return msg

    def info(self, msg, **kwargs):
        self._logger.info(self._fmt(msg, **kwargs))

    def warning(self, msg, **kwargs):
        self._logger.warning(self._fmt(msg, **kwargs))

    def error(self, msg, **kwargs):
        self._logger.error(self._fmt(msg, **kwargs))

    def debug(self, msg, **kwargs):
        self._logger.debug(self._fmt(msg, **kwargs))


__all__ = ["WAFConfig", "get_config", "reload_config", "ForensicLogger", "WAFLogger"]
