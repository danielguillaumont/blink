"""``blink daemon``: scheduled scans with retries, missed-run detection and alert delivery.

One APScheduler job per target (interval or cron, with jitter; one instance at a time) runs
on a thread pool whose size is the concurrency limit. Each job opens its own store
connection and browser. An hourly job, and every daemon start, checks how long each
target/profile has gone without a successful evaluation; overdue ones become
``schedule.missed_evaluation`` findings, and overdue targets are scanned immediately.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .alerts import Notification
from .alerts.delivery import Dispatcher
from .config import TargetConfig, parse_duration
from .project import Project
from .scan import STATUS_CAPTURE_FAILED, STATUS_OK, ScanReport, blink_version, record_findings, scan
from .schedule import capture_failed, last_successful_evaluations, missed_evaluations, period
from .schedule import trigger_for as schedule_trigger
from .store import Store, utc_now

CHECK_EVERY = timedelta(hours=1)


def _now() -> datetime:
    return datetime.now(UTC)


def _parse(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


@dataclass
class Daemon:
    project: Project
    capturer_factory: Callable[[], Any] | None = None
    now: Callable[[], datetime] = _now
    sleep: Callable[[float], None] = time.sleep
    log: Any = None
    concurrency: int = 2
    _stop: threading.Event = field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        if self.log is None:
            from .logsetup import configure

            self.log = configure()

    # -- helpers -----------------------------------------------------------------------
    def open_store(self) -> Store:
        return self.project.open_store()

    def _capturer(self) -> Any:
        if self.capturer_factory is not None:
            return self.capturer_factory()
        from .capture.browser import Capturer

        return Capturer()

    def _dispatch(self, store: Store, notifications: tuple[Notification, ...]) -> None:
        if not notifications or not self.project.config.alerts.sinks:
            return
        dispatcher = Dispatcher.from_config(
            store,
            self.project.config.alerts,
            base=self.project.root,
            version=blink_version(),
            sleep=self.sleep,
            log=self.log.info,
        )
        dispatcher.dispatch(notifications)

    def monitoring_since(self, store: Store) -> datetime:
        """When monitoring started: the first daemon start in the ledger, else now."""
        row = store.db.query_one(
            "SELECT at FROM ledger WHERE kind = 'daemon.started' ORDER BY seq LIMIT 1"
        )
        return _parse(row["at"]) if row else self.now()

    # -- jobs ------------------------------------------------------------------------------
    def run_target(self, target: TargetConfig) -> list[ScanReport]:
        """Scan one target; retry failed captures with exponential backoff."""
        schedule = self.project.config.schedule_for(target)
        backoff = parse_duration(schedule.retry_backoff).total_seconds()
        pending = list(target.profiles)
        errors: dict[str, str] = {}
        reports: list[ScanReport] = []
        attempts = 0
        self.log.info("scan.started", target=target.name, profiles=pending)
        with self.open_store() as store, self._capturer() as capturer:
            for attempt in range(schedule.retries + 1):
                attempts += 1
                report = scan(
                    self.project,
                    store,
                    [target],
                    capturer,
                    profiles=pending,
                    fail_on=None,
                    now=self.now(),
                )
                reports.append(report)
                self._dispatch(store, report.notifications)
                failed = [r for r in report.results if r.status == STATUS_CAPTURE_FAILED]
                errors = {r.profile: r.error or "capture failed" for r in failed}
                pending = [r.profile for r in failed]
                self.log.info(
                    "scan.finished",
                    target=target.name,
                    run_id=report.run_id,
                    attempt=attempts,
                    findings=len(report.findings),
                    max_severity=report.max_severity.label if report.max_severity else None,
                    failed_profiles=pending,
                )
                if not pending:
                    break
                if attempt < schedule.retries:
                    self.sleep(backoff * (2**attempt))
            if pending:
                findings = [capture_failed(target.name, p, errors[p], attempts) for p in pending]
                failure = record_findings(self.project, store, findings, now=self.now())
                reports.append(failure)
                self._dispatch(store, failure.notifications)
                self.log.warning("scan.capture_failed", target=target.name, profiles=pending)
        return reports

    def safe_run_target(self, target: TargetConfig) -> None:
        try:
            self.run_target(target)
        except Exception as exc:  # a job must never kill the scheduler
            self.log.error("scan.crashed", target=target.name, error=f"{type(exc).__name__}: {exc}")

    def check_schedule(self) -> ScanReport | None:
        """Record a finding for every target/profile without a recent successful evaluation."""
        with self.open_store() as store:
            now = self.now()
            findings = missed_evaluations(
                self.project.config, store, now=now, since=self.monitoring_since(store)
            )
            if not findings:
                return None
            report = record_findings(self.project, store, findings, now=now)
            self._dispatch(store, report.notifications)
        self.log.warning("schedule.missed", subjects=[f.subject for f in findings])
        return report

    def due_targets(self) -> list[TargetConfig]:
        """Targets with a profile whose last success is older than one period (or never)."""
        with self.open_store() as store:
            last = last_successful_evaluations(store)
        now = self.now()
        due = []
        for target in self.project.config.targets:
            every = period(self.project.config.schedule_for(target), now=now)
            if any(
                (seen := last.get((target.name, p))) is None or now - seen >= every
                for p in target.profiles
            ):
                due.append(target)
        return due

    def run_once(self) -> int:
        """Scan every target now, then check the schedule. Exit 0, or 3 if captures failed."""
        failed = False
        self._started("once")
        for target in self.project.config.targets:
            reports = self.run_target(target)
            ok = {
                (r.target, r.profile)
                for rep in reports
                for r in rep.results
                if r.status == STATUS_OK
            }
            failed |= any((target.name, p) not in ok for p in target.profiles)
        self.check_schedule()
        return 3 if failed else 0

    # -- long-running --------------------------------------------------------------------------
    def _started(self, mode: str) -> None:
        with self.open_store() as store:
            store.ledger.append(
                "daemon.started",
                {"mode": mode, "targets": [t.name for t in self.project.config.targets]},
                at=utc_now(),
            )

    def build_scheduler(self) -> Any:
        from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_MISSED
        from apscheduler.executors.pool import ThreadPoolExecutor
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.interval import IntervalTrigger

        scheduler = BackgroundScheduler(
            executors={"default": ThreadPoolExecutor(max_workers=max(1, self.concurrency))},
            job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600},
            timezone=UTC,
        )
        for target in self.project.config.targets:
            schedule = self.project.config.schedule_for(target)
            scheduler.add_job(
                self.safe_run_target,
                trigger=schedule_trigger(schedule, start=self.now()),
                args=[target],
                id=f"scan:{target.name}",
                name=f"scan {target.name}",
            )
        scheduler.add_job(
            self.check_schedule,
            trigger=IntervalTrigger(seconds=int(CHECK_EVERY.total_seconds()), timezone=UTC),
            id="schedule-check",
            name="missed-evaluation check",
        )

        def on_event(event: Any) -> None:
            if event.code == EVENT_JOB_MISSED:
                self.log.warning("schedule.job_missed", job=event.job_id)
                self.check_schedule()
            elif event.code == EVENT_JOB_ERROR:  # pragma: no cover - safe_run_target catches
                self.log.error("schedule.job_error", job=event.job_id)

        scheduler.add_listener(on_event, EVENT_JOB_MISSED | EVENT_JOB_ERROR)
        return scheduler

    def serve_forever(self, *, metrics_host: str | None, metrics_port: int | None) -> int:
        metrics_store = None
        if metrics_port is not None:
            from prometheus_client import start_http_server

            from .metrics import registry_for

            metrics_store = self.open_store()
            start_http_server(
                metrics_port, addr=metrics_host or "127.0.0.1", registry=registry_for(metrics_store)
            )
            self.log.info("metrics.listening", host=metrics_host, port=metrics_port)
        self._started("daemon")
        scheduler = self.build_scheduler()
        scheduler.start()
        self.log.info("daemon.started", jobs=[j.id for j in scheduler.get_jobs()])
        self.check_schedule()
        for target in self.due_targets():
            scheduler.add_job(self.safe_run_target, args=[target], id=f"catch-up:{target.name}")
        try:
            while not self._stop.wait(1.0):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            scheduler.shutdown(wait=True)
            if metrics_store is not None:
                metrics_store.close()
            self.log.info("daemon.stopped")
        return 0

    def stop(self) -> None:
        self._stop.set()
