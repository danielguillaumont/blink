"""Prometheus metrics computed from the store on each scrape.

Reading the SQLite index (instead of keeping in-process counters) keeps the numbers correct
across ``blink scan`` from CI, ``blink daemon`` and ``blink serve``, and across restarts.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .findings import Severity

if TYPE_CHECKING:
    from .store import Store


def _timestamp(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


class StoreCollector:
    def __init__(self, store: Store) -> None:
        self.store = store

    def describe(self) -> list[Any]:
        return []  # metrics are dynamic; skip registry-time collection

    def collect(self) -> Iterator[Any]:
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

        db = self.store.db
        scans = CounterMetricFamily(
            "blink_scans", "Scan runs recorded, by final status", labels=["status"]
        )
        for row in db.query(
            "SELECT status, COUNT(*) AS n FROM runs WHERE kind = 'scan' GROUP BY status"
        ):
            scans.add_metric([row["status"]], float(row["n"]))
        yield scans

        findings = CounterMetricFamily(
            "blink_findings", "Findings recorded across all runs, by severity", labels=["severity"]
        )
        counts = {
            int(r["severity"]): int(r["n"])
            for r in db.query("SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity")
        }
        for severity in Severity:
            findings.add_metric([severity.label], float(counts.get(int(severity), 0)))
        yield findings

        last = GaugeMetricFamily(
            "blink_last_successful_scan_timestamp",
            "Unix time of the last successful evaluation of each target/profile",
            labels=["target", "profile"],
        )
        for row in db.query(
            "SELECT rr.target, rr.profile, MAX(r.finished_at) AS at FROM run_results rr "
            "JOIN runs r ON r.id = rr.run_id WHERE rr.status = 'ok' AND r.kind = 'scan' "
            "GROUP BY rr.target, rr.profile"
        ):
            last.add_metric([row["target"], row["profile"]], _timestamp(row["at"]))
        yield last

        alerts = GaugeMetricFamily(
            "blink_alerts", "Alerts by state and severity", labels=["state", "severity"]
        )
        for row in db.query(
            "SELECT state, severity, COUNT(*) AS n FROM alerts GROUP BY state, severity"
        ):
            alerts.add_metric([row["state"], Severity(int(row["severity"])).label], float(row["n"]))
        yield alerts

        dead = CounterMetricFamily(
            "blink_alert_dead_letters", "Notifications that could not be delivered"
        )
        total = db.query_one("SELECT COUNT(*) AS n FROM ledger WHERE kind = 'alert.dead_letter'")
        dead.add_metric([], float(total["n"] if total else 0))
        yield dead


def registry_for(store: Store) -> Any:
    from prometheus_client import CollectorRegistry

    registry = CollectorRegistry(auto_describe=False)
    registry.register(StoreCollector(store))
    return registry


def render(store: Store) -> bytes:
    from prometheus_client import generate_latest

    data: bytes = generate_latest(registry_for(store))
    return data
