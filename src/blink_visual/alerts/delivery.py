"""Deliver notifications with retries and exponential backoff; dead-letter the rest."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import AlertsConfig, SinkConfig, parse_duration
from ..errors import BlinkError
from ..findings import Severity
from ..store import Store, utc_now
from . import Notification
from .sinks import DeliveryError, Sink, build_sink

MAX_BACKOFF_S = 300.0


@dataclass(frozen=True)
class DeliveryResult:
    sink: str
    alert_id: str
    delivered: bool
    attempts: int
    error: str | None = None


@dataclass
class Dispatcher:
    """Routes notifications to configured sinks by severity."""

    store: Store
    config: AlertsConfig
    sinks: Sequence[tuple[SinkConfig, Sink]]
    sleep: Callable[[float], None] = time.sleep
    log: Callable[..., None] = field(default=lambda event, **kw: None)

    @classmethod
    def from_config(
        cls,
        store: Store,
        config: AlertsConfig,
        *,
        base: Path,
        version: str,
        sleep: Callable[[float], None] = time.sleep,
        log: Callable[..., None] | None = None,
    ) -> Dispatcher:
        pairs = [(c, build_sink(c, base=base, version=version)) for c in config.sinks]
        return cls(store, config, pairs, sleep, log or (lambda event, **kw: None))

    @property
    def dead_letter_path(self) -> Path:
        return self.store.root / self.config.dead_letter

    def dispatch(self, notifications: Sequence[Notification]) -> list[DeliveryResult]:
        results: list[DeliveryResult] = []
        default = Severity.parse(self.config.min_severity)
        for notification in notifications:
            for config, sink in self.sinks:
                minimum = Severity.parse(config.min_severity) if config.min_severity else default
                if notification.alert.severity < minimum:
                    continue
                results.append(self._deliver(sink, notification))
        return results

    def _deliver(self, sink: Sink, notification: Notification) -> DeliveryResult:
        attempts = 0
        error = ""
        backoff = parse_duration(self.config.backoff).total_seconds()
        for attempt in range(self.config.retries + 1):
            attempts += 1
            try:
                sink.send(notification)
            except (DeliveryError, BlinkError) as exc:
                error = str(exc)
                self.log(
                    "alert.delivery_failed",
                    sink=sink.name,
                    alert=notification.alert.id,
                    attempt=attempts,
                    error=error,
                )
                if attempt < self.config.retries:
                    self.sleep(min(MAX_BACKOFF_S, backoff * (2**attempt)))
                continue
            self.log(
                "alert.delivered", sink=sink.name, alert=notification.alert.id, attempts=attempts
            )
            return DeliveryResult(sink.name, notification.alert.id, True, attempts)
        self._dead_letter(sink.name, notification, error, attempts)
        return DeliveryResult(sink.name, notification.alert.id, False, attempts, error)

    def _dead_letter(self, sink: str, n: Notification, error: str, attempts: int) -> None:
        at = utc_now()
        record: dict[str, Any] = {
            "at": at,
            "sink": sink,
            "attempts": attempts,
            "error": error,
            "notification": n.to_dict(),
        }
        self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dead_letter_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.store.ledger.append(
            "alert.dead_letter",
            {"sink": sink, "alert": n.alert.id, "attempts": attempts, "error": error},
            at=at,
        )
        self.log("alert.dead_lettered", sink=sink, alert=n.alert.id, attempts=attempts)
