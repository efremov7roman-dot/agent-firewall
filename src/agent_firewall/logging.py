"""Minimal structured logging foundation for Agent Firewall."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import IO, Any


class JsonFormatter(logging.Formatter):
    """Render a log record as one JSON object without security-sensitive internals."""

    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info is not None:
            event["exception"] = self.formatException(record.exc_info)
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def configure_logging(
    *, level: int = logging.INFO, stream: IO[str] | None = None
) -> logging.Logger:
    """Configure and return the package logger with a single JSON stream handler."""

    logger = logging.getLogger("agent_firewall")
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
