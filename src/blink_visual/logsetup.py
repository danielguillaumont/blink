"""structlog configuration: JSON lines on stderr for the daemon and server.

Never log secrets: callers pass sink names, alert ids and target names, never URLs with
credentials, cookies, headers or form data.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

REDACTED = "[redacted]"
SENSITIVE_KEYS = frozenset({"authorization", "cookie", "password", "token", "secret", "url"})


def _redact(_: Any, __: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for key in list(event):
        if key.lower() in SENSITIVE_KEYS:
            event[key] = REDACTED
    return event


def configure(*, json: bool = True, level: str = "info") -> Any:
    import structlog

    renderer: Any = (
        structlog.processors.JSONRenderer(sort_keys=True)
        if json
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()]
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )
    return structlog.get_logger("blink")
