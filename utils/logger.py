
"""
Structured Logging for Transformer WAF
Provides JSON-formatted logs with support for alerts and metrics
"""

import logging
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from logging.handlers import RotatingFileHandler


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add custom fields from extra
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)

    
class WAFLogger:
    """
    Centralized logger for the WAF system with support for
    structured logging and separate alert logging.
    """

    def __init__(
        self,
        name: str = "transformer_waf",
        level: str = "INFO",
        log_file: Optional[str] = None,
        json_format: bool = True,
        alert_log_file: Optional[str] = None
    ):
        """
        Initialize WAF logger.

        Args:
            name: Logger name
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (optional)
            json_format: Use JSON formatting
            alert_log_file: Separate file for anomaly alerts
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.logger.handlers.clear()  # Remove existing handlers

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        if json_format:
            console_handler.setFormatter(JSONFormatter())
        else:
            console_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
        self.logger.addHandler(console_handler)

        # File handler (if specified)
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=100 * 1024 * 1024,  # 100MB
                backupCount=5
            )
            if json_format:
                file_handler.setFormatter(JSONFormatter())
            else:
                file_handler.setFormatter(
                    logging.Formatter(
                        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                    )
                )
            self.logger.addHandler(file_handler)

        # Alert handler (for anomaly alerts)
        self.alert_logger = None
        if alert_log_file:
            Path(alert_log_file).parent.mkdir(parents=True, exist_ok=True)
            self.alert_logger = logging.getLogger(f"{name}.alerts")
            self.alert_logger.setLevel(logging.INFO)
            self.alert_logger.propagate = False

            alert_handler = RotatingFileHandler(
                alert_log_file,
                maxBytes=50 * 1024 * 1024,  # 50MB
                backupCount=10
            )
            alert_handler.setFormatter(JSONFormatter())
            self.alert_logger.addHandler(alert_handler)

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self._log(logging.CRITICAL, message, **kwargs)

    def _log(self, level: int, message: str, **kwargs):
        """Internal logging method with extra fields"""
        extra = {"extra_fields": kwargs} if kwargs else {}
        self.logger.log(level, message, extra=extra)