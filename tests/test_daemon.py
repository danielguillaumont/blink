"""Phase 4 AC: frozen-clock scheduling and missed-run detection; daemon retries; metrics."""

from __future__ import annotations

import itertools
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from helpers import snapshot

from blink_visual.config import ScheduleConfig, parse_config, parse_duration
from blink_visual.errors import CaptureError
from blink_visual.findings import Severity
from blink_visual.project import Project
from blink_visual.schedule import fire_times, max_gap, missed_evaluations, period

pytest.importorskip("apscheduler")

T0 = datetime(2026, 11, 2, 0, 0, tzinfo=UTC)  # a Monday
SNAPSHOT_IDS = itertools.count(1)


class FrozenClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **delta: float) -> None:
        self.current += timedelta(**delta)


# --- pure scheduling ---------------------------------------------------------------


def test_duration_parsing():
    assert parse_duration("90s") == timedelta(seconds=90)
    assert parse_duration("1.5h") == timedelta(minutes=90)
    assert parse_duration("1w") == timedelta(days=7)
    assert parse_duration(30) == timedelta(seconds=30)
    with pytest.raises(ValueError, match="invalid duration"):
        parse_duration("soon")


def test_interval_fire_times_are_deterministic():
    schedule = ScheduleConfig(interval="1d")
    times = fire_times(schedule, now=T0, count=3)
    assert times == [T0, T0 + timedelta(days=1), T0 + timedelta(days=2)]
    assert period(schedule, now=T0) == timedelta(days=1)


def test_default_schedule_is_weekly():
    schedule = ScheduleConfig()
    times = fire_times(schedule, now=T0, count=2)
    assert times[1] - times[0] == timedelta(days=7)
    assert max_gap(schedule, now=T0) == timedelta(days=7)


def test_cron_fire_times_and_period():
    schedule = ScheduleConfig(cron="0 3 * * 1-5")  # 03:00 on weekdays
    times = fire_times(schedule, now=T0, count=6)
    assert times[0] == T0.replace(hour=3)
    assert all(t.hour == 3 and t.weekday() < 5 for t in times)
    assert times[5] == T0.replace(hour=3) + timedelta(days=7)  # skips the weekend
    assert period(schedule, now=T0) == timedelta(days=3)  # Friday → Monday


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("1-5", "mon-fri"),
        ("0", "sun"),
        ("7", "sun"),
        ("0-6", "sun,mon-sat"),
        ("5-7", "sun,fri-sat"),
        ("1,3,5", "mon,wed,fri"),
        ("mon-fri", "mon-fri"),
        ("*", "*"),
        ("*/2", "*/2"),
    ],
)
def test_crontab_weekday_numbers_follow_crontab(field, expected):
    from blink_visual.schedule import crontab_weekdays

    assert crontab_weekdays(field) == expected


@pytest.mark.parametrize("field", ["8", "5-2", "1-5/2"])
def test_invalid_crontab_weekdays(field):
    from blink_visual.schedule import crontab_weekdays

    with pytest.raises(ValueError):
        crontab_weekdays(field)
    with pytest.raises(Exception, match="weekday"):
        ScheduleConfig(cron=f"0 3 * * {field}")


def test_max_gap_defaults_and_override():
    daily = ScheduleConfig(interval="1d", jitter="0s", retries=0, retry_backoff="0s")
    assert max_gap(daily, now=T0) == timedelta(hours=36)
    assert max_gap(daily.model_copy(update={"max_gap": "2h"}), now=T0) == timedelta(hours=2)


def test_schedule_validation_and_target_override():
    with pytest.raises(Exception, match="either interval or cron"):
        ScheduleConfig(interval="1d", cron="0 3 * * *")
    with pytest.raises(Exception, match="five fields"):
        ScheduleConfig(cron="0 3 * *")
    with pytest.raises(Exception, match="at least 1m"):
        ScheduleConfig(interval="10s")
    config = parse_config(
        {
            "schedule": {"interval": "1d", "retries": 4},
            "targets": [
                {"name": "a", "url": "http://127.0.0.1:1", "schedule": {"cron": "0 * * * *"}},
                {"name": "b", "url": "http://127.0.0.1:1"},
            ],
        }
    )
    a = config.schedule_for(config.targets[0])
    assert (a.cron, a.interval, a.retries) == ("0 * * * *", None, 4)
    assert config.schedule_for(config.targets[1]).interval == "1d"


# --- missed evaluations (frozen clock) ------------------------------------------------------


def _project(tmp_path, schedule: dict | None = None) -> Project:
    data = {
        "schedule": schedule
        or {"interval": "1d", "jitter": "0s", "retries": 0, "retry_backoff": "0s"},
        "targets": [{"name": "checkout", "url": "https://shop.example/checkout"}],
    }
    path = tmp_path / "blink.yaml"
    path.write_text(yaml.safe_dump(data), "utf-8")
    return Project.load(path)


def _record_success(store, at: datetime, run_id: str) -> None:
    stamp = at.isoformat().replace("+00:00", "Z")
    with store.db.transaction() as conn:
        conn.execute(
            "INSERT INTO runs (id, kind, started_at, finished_at, status) "
            "VALUES (?, 'scan', ?, ?, 'clean')",
            (run_id, stamp, stamp),
        )
        conn.execute(
            "INSERT INTO run_results (run_id, target, profile, status) "
            "VALUES (?, 'checkout', 'desktop-chrome', 'ok')",
            (run_id,),
        )


def test_missed_evaluation_with_frozen_clock(tmp_path):
    project = _project(tmp_path)
    with project.open_store() as store:
        _record_success(store, T0, "run-1")
        config = project.config
        # 35 h after the last success: within 1.5 days.
        assert missed_evaluations(config, store, now=T0 + timedelta(hours=35), since=T0) == []
        # 37 h: one daily run was missed.
        (finding,) = missed_evaluations(config, store, now=T0 + timedelta(hours=37), since=T0)
        assert finding.detector == "schedule"
        assert finding.change_type == "missed_evaluation"
        assert finding.subject == "checkout/desktop-chrome"
        assert finding.attributes["gap_hours"] == 37
        assert finding.attributes["never_evaluated"] is False
        assert finding.evidence["last_success"] == "2026-11-02T00:00:00Z"
        # A newer success clears it.
        _record_success(store, T0 + timedelta(hours=36), "run-2")
        assert missed_evaluations(config, store, now=T0 + timedelta(hours=37), since=T0) == []


def test_never_evaluated_is_measured_from_monitoring_start(tmp_path):
    project = _project(tmp_path)
    with project.open_store() as store:
        none = missed_evaluations(project.config, store, now=T0 + timedelta(hours=1), since=T0)
        assert none == []
        (finding,) = missed_evaluations(project.config, store, now=T0 + timedelta(days=2), since=T0)
        assert finding.attributes["never_evaluated"] is True


def test_missed_weekly_evaluation_is_critical(tmp_path):
    from blink_visual.rules import RuleEngine

    project = _project(tmp_path, {"interval": "1w"})
    with project.open_store() as store:
        _record_success(store, T0, "run-1")
        (finding,) = missed_evaluations(project.config, store, now=T0 + timedelta(days=8), since=T0)
    graded = RuleEngine().grade(finding)
    assert finding.attributes["over_a_week"] is True
    assert graded.severity == Severity.CRITICAL
    assert "11.6.1" in graded.why


# --- daemon with a fake capturer -------------------------------------------------------------


class FakeCapturer:
    """Returns the same snapshot every time; fails the first ``failures`` captures."""

    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.calls = 0
        self.ids = SNAPSHOT_IDS

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def capture(self, target, profile_name, profile, store):
        self.calls += 1
        if self.calls <= self.failures:
            raise CaptureError(f"timeout loading {target.url}")
        snap = snapshot(id=f"snap-{next(self.ids)}", target=target.name, profile=profile_name)
        store.ensure_target(target.name, target.url)
        return snap


class NullLog:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def _log(self, event, **kw):
        self.events.append((event, kw))

    info = warning = error = _log


@pytest.fixture
def daemon_factory(tmp_path):
    from blink_visual.daemon import Daemon

    def make(capturer: FakeCapturer, clock: FrozenClock | None = None, **schedule):
        project = _project(
            tmp_path,
            {"interval": "1d", "jitter": "0s", "retries": 2, "retry_backoff": "10s", **schedule},
        )
        sleeps: list[float] = []
        daemon = Daemon(
            project,
            capturer_factory=lambda: capturer,
            now=clock or FrozenClock(T0),
            sleep=sleeps.append,
            log=NullLog(),
        )
        failures, capturer.failures = capturer.failures, 0
        with project.open_store() as store:
            snap = capturer.capture(project.config.targets[0], "desktop-chrome", None, store)
            store.save_snapshot(snap)
            store.set_baseline(snap.target, snap.profile, snap.id)
        capturer.failures, capturer.calls = failures, 0
        return daemon, sleeps

    return make


def test_run_target_succeeds_and_records_the_run(daemon_factory):
    daemon, sleeps = daemon_factory(FakeCapturer())
    (report,) = daemon.run_target(daemon.project.config.targets[0])
    assert report.results[0].status == "ok"
    assert sleeps == []
    with daemon.open_store() as store:
        assert store.ledger.verify().ok
        assert [r.kind for r in store.ledger.records()][-1] == "run.scan"


def test_run_target_retries_with_backoff(daemon_factory):
    capturer = FakeCapturer(failures=2)
    daemon, sleeps = daemon_factory(capturer)
    reports = daemon.run_target(daemon.project.config.targets[0])
    assert [r.results[0].status for r in reports] == ["capture_failed", "capture_failed", "ok"]
    assert sleeps == [10.0, 20.0]


def test_run_target_gives_up_with_a_capture_failed_alert(daemon_factory):
    capturer = FakeCapturer(failures=99)
    daemon, sleeps = daemon_factory(capturer)
    reports = daemon.run_target(daemon.project.config.targets[0])
    assert len(reports) == 4  # three attempts + the failure record
    assert sleeps == [10.0, 20.0]
    failure = reports[-1]
    (finding,) = failure.findings
    assert (finding.detector, finding.change_type) == ("schedule", "capture_failed")
    assert finding.severity == Severity.HIGH
    assert finding.attributes["attempts"] == 3
    assert [n.event for n in failure.notifications] == ["opened"]


def test_check_schedule_and_due_targets_with_frozen_clock(daemon_factory):
    clock = FrozenClock(T0)
    daemon, _ = daemon_factory(FakeCapturer(), clock)
    daemon._started("test")  # monitoring starts at T0 (real clock is used for the ledger)
    with daemon.open_store() as store, store.db.transaction() as conn:
        conn.execute(
            "UPDATE ledger SET at = ? WHERE kind = 'daemon.started'", ("2026-11-02T00:00:00Z",)
        )
    assert daemon.due_targets()  # never evaluated
    daemon.run_target(daemon.project.config.targets[0])
    assert daemon.due_targets() == []
    clock.advance(hours=20)
    assert daemon.check_schedule() is None
    clock.advance(hours=20)  # 40 h without a success
    # Move the success back to T0 on the frozen clock.
    with daemon.open_store() as store, store.db.transaction() as conn:
        conn.execute("UPDATE runs SET finished_at = '2026-11-02T00:00:00Z'")
    report = daemon.check_schedule()
    assert report is not None
    (finding,) = report.findings
    assert finding.change_type == "missed_evaluation"
    assert [n.event for n in report.notifications] == ["opened"]
    # The same overdue target an hour later is deduplicated: no second notification.
    clock.advance(hours=1)
    again = daemon.check_schedule()
    assert again is not None
    assert again.notifications == ()
    assert daemon.due_targets() == [daemon.project.config.targets[0]]


def test_run_once_exit_codes(daemon_factory):
    daemon, _ = daemon_factory(FakeCapturer())
    assert daemon.run_once() == 0
    failing, _ = daemon_factory(FakeCapturer(failures=99))
    assert failing.run_once() == 3


def test_scheduler_jobs_and_triggers(daemon_factory):
    clock = FrozenClock(T0)
    daemon, _ = daemon_factory(FakeCapturer(), clock)
    scheduler = daemon.build_scheduler()
    jobs = {job.id: job for job in scheduler.get_jobs()}
    assert set(jobs) == {"scan:checkout", "schedule-check"}
    trigger = jobs["scan:checkout"].trigger
    first = trigger.get_next_fire_time(None, T0)
    assert first == T0
    assert trigger.get_next_fire_time(first, first) == T0 + timedelta(days=1)
    assert scheduler._executors["default"]._pool._max_workers == 2  # concurrency limit
    assert scheduler._job_defaults["max_instances"] == 1
    assert scheduler._job_defaults["coalesce"] is True


def test_dispatch_to_jsonl_sink(daemon_factory, tmp_path):
    capturer = FakeCapturer(failures=99)
    daemon, _ = daemon_factory(capturer)
    alerts = {"sinks": [{"name": "file", "type": "jsonl", "path": "alerts.jsonl"}]}
    daemon.project = replace(
        daemon.project,
        config=daemon.project.config.model_copy(
            update={"alerts": parse_config({"alerts": alerts}).alerts}
        ),
    )
    daemon.run_target(daemon.project.config.targets[0])
    lines = (tmp_path / "alerts.jsonl").read_text("utf-8").splitlines()
    assert json.loads(lines[0])["change_type"] == "capture_failed"


# --- metrics -----------------------------------------------------------------------------------


def test_metrics_from_store(daemon_factory):
    pytest.importorskip("prometheus_client")
    from blink_visual.metrics import render

    daemon, _ = daemon_factory(FakeCapturer())
    daemon.run_target(daemon.project.config.targets[0])
    with daemon.open_store() as store:
        text = render(store).decode()
    assert 'blink_scans_total{status="clean"} 1.0' in text
    assert 'blink_findings_total{severity="high"} 0.0' in text
    assert (
        'blink_last_successful_scan_timestamp{profile="desktop-chrome",target="checkout"}' in text
    )
    assert "blink_alert_dead_letters_total 0.0" in text


def test_logs_are_json_and_redacted(capsys):
    pytest.importorskip("structlog")
    from blink_visual.logsetup import configure

    log = configure()
    log.info("alert.delivered", sink="slack", url="https://hooks.example/secret", alert="abc")
    line = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert line["event"] == "alert.delivered"
    assert line["url"] == "[redacted]"
    assert line["level"] == "info"
    assert "timestamp" in line


def test_serve_forever_runs_catch_up_and_serves_metrics(daemon_factory):
    import socket
    import threading
    import time
    import urllib.request

    pytest.importorskip("prometheus_client")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    capturer = FakeCapturer()
    daemon, _ = daemon_factory(capturer, FrozenClock(datetime.now(UTC)))
    thread = threading.Thread(
        target=daemon.serve_forever,
        kwargs={"metrics_host": "127.0.0.1", "metrics_port": port},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 30
    body = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as r:
                body = r.read().decode()
            if 'blink_scans_total{status="clean"}' in body:
                break
        except OSError:
            pass
        time.sleep(0.2)
    daemon.stop()
    thread.join(30)
    assert not thread.is_alive()
    assert capturer.calls >= 1  # the never-evaluated target was scanned on start
    assert 'blink_scans_total{status="clean"}' in body
    events = [e for e, _ in daemon.log.events]
    assert "daemon.started" in events
    assert events[-1] == "daemon.stopped"
