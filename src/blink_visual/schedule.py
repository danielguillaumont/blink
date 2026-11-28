"""Scheduling policy and missed-evaluation detection (PCI DSS 11.6.1 "at least weekly").

Everything here takes an explicit ``now`` so it can be tested with a frozen clock. The
daemon (``daemon.py``) turns these into APScheduler jobs.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import TYPE_CHECKING, Any

from .config import BlinkConfig, ScheduleConfig, TargetConfig, parse_duration
from .findings import Finding

if TYPE_CHECKING:
    from .store import Store

WEEK = timedelta(days=7)
DEFAULT_INTERVAL = WEEK
"""PCI DSS 11.6.1 requires at least weekly evaluation; Blink recommends daily."""


_WEEKDAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat", "sun")


def crontab_weekdays(field: str) -> str:
    """Translate crontab weekday numbers (0 or 7 = Sunday) to names.

    APScheduler 3 numbers weekdays from Monday = 0, so ``1-5`` would silently mean
    Tuesday to Saturday. Names (``mon-fri``) mean the same in both and pass through.
    """
    parts: list[str] = []
    for token in field.split(","):
        base, _, step = token.partition("/")
        if not any(ch.isdigit() for ch in base):
            parts.append(token)
            continue
        if step:
            raise ValueError("use weekday names (mon-fri) with a step in the cron weekday field")
        start, _, end = base.partition("-")
        first, last = int(start), int(end) if end else None
        if not 0 <= first <= 7 or (last is not None and not first <= last <= 7):
            raise ValueError(f"invalid cron weekday {token!r}")
        if last is None:
            parts.append(_WEEKDAYS[first])
        elif first == 0 or last == 7:
            # Sunday at either end of a range: list it separately.
            inner = (max(first, 1), min(last, 6))
            parts.append("sun")
            if inner[0] <= inner[1]:
                parts.append(f"{_WEEKDAYS[inner[0]]}-{_WEEKDAYS[inner[1]]}")
        else:
            parts.append(f"{_WEEKDAYS[first]}-{_WEEKDAYS[last]}")
    return ",".join(parts)


def trigger_for(schedule: ScheduleConfig, *, start: datetime | None = None) -> Any:
    """The APScheduler trigger for ``schedule`` (interval, cron, or the weekly default)."""
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger

    jitter = int(parse_duration(schedule.jitter).total_seconds()) or None
    if schedule.cron is not None:
        minute, hour, day, month, weekday = schedule.cron.split()
        return CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=crontab_weekdays(weekday),
            timezone=UTC,
            jitter=jitter,
        )
    interval = parse_duration(schedule.interval) if schedule.interval else DEFAULT_INTERVAL
    return IntervalTrigger(
        seconds=int(interval.total_seconds()), start_date=start, timezone=UTC, jitter=jitter
    )


def fire_times(schedule: ScheduleConfig, *, now: datetime, count: int) -> list[datetime]:
    """The next ``count`` fire times after ``now``, ignoring jitter (deterministic)."""
    unjittered = schedule.model_copy(update={"jitter": 0})
    trigger = trigger_for(unjittered, start=now)
    times: list[datetime] = []
    previous: datetime | None = None
    cursor = now
    for _ in range(count):
        nxt = trigger.get_next_fire_time(previous, cursor)
        if nxt is None:  # pragma: no cover - interval and cron triggers never end
            break
        times.append(nxt)
        previous, cursor = nxt, nxt
    return times


def period(schedule: ScheduleConfig, *, now: datetime) -> timedelta:
    """The scheduled time between evaluations (the longest gap for irregular crons)."""
    if schedule.cron is None:
        return parse_duration(schedule.interval) if schedule.interval else DEFAULT_INTERVAL
    times = fire_times(schedule, now=now, count=8)
    return max(b - a for a, b in pairwise(times))


def max_gap(schedule: ScheduleConfig, *, now: datetime) -> timedelta:
    """How long without a successful evaluation before it counts as missed.

    Explicit ``max_gap`` wins. Otherwise one and a half periods plus the jitter and the retry
    budget, so a single missed run is detected; never more than a week (11.6.1).
    """
    if schedule.max_gap is not None:
        return parse_duration(schedule.max_gap)
    every = period(schedule, now=now)
    slack = parse_duration(schedule.jitter) + parse_duration(schedule.retry_backoff) * (
        2 ** (schedule.retries + 1)
    )
    gap: timedelta = min(WEEK, every * 1.5 + slack)
    return gap


def _parse(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def last_successful_evaluations(store: Store) -> dict[tuple[str, str], datetime]:
    rows = store.db.query(
        "SELECT rr.target, rr.profile, MAX(r.finished_at) AS at FROM run_results rr "
        "JOIN runs r ON r.id = rr.run_id WHERE rr.status = 'ok' AND r.kind = 'scan' "
        "GROUP BY rr.target, rr.profile"
    )
    return {(r["target"], r["profile"]): _parse(r["at"]) for r in rows}


def missed_evaluations(
    config: BlinkConfig,
    store: Store,
    *,
    now: datetime,
    since: datetime,
    targets: Iterable[TargetConfig] | None = None,
) -> list[Finding]:
    """A ``schedule.missed_evaluation`` finding per target/profile overdue at ``now``.

    ``since`` is when monitoring started (the daemon's first start); a target that was never
    evaluated is measured from then.
    """
    last = last_successful_evaluations(store)
    findings: list[Finding] = []
    for target in targets if targets is not None else config.targets:
        schedule = config.schedule_for(target)
        allowed = max_gap(schedule, now=now)
        for profile in target.profiles:
            seen = last.get((target.name, profile))
            reference = seen or since
            gap = now - reference
            if gap <= allowed:
                continue
            findings.append(
                Finding(
                    detector="schedule",
                    change_type="missed_evaluation",
                    subject=f"{target.name}/{profile}",
                    title=(
                        f"No successful evaluation of {target.name} [{profile}] for "
                        f"{_human(gap)} (allowed: {_human(allowed)})"
                    ),
                    target=target.name,
                    profile=profile,
                    attributes={
                        "gap_hours": round(gap.total_seconds() / 3600, 2),
                        "max_gap_hours": round(allowed.total_seconds() / 3600, 2),
                        "never_evaluated": seen is None,
                        "over_a_week": gap > WEEK,
                    },
                    evidence={
                        "last_success": None if seen is None else _iso(seen),
                        "checked_at": _iso(now),
                    },
                )
            )
    return findings


def capture_failed(target: str, profile: str, error: str, attempts: int) -> Finding:
    return Finding(
        detector="schedule",
        change_type="capture_failed",
        subject=f"{target}/{profile}",
        title=f"Scheduled scan of {target} [{profile}] failed after {attempts} attempt(s)",
        target=target,
        profile=profile,
        attributes={"attempts": attempts},
        evidence={"error": error[:500]},
    )


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _human(delta: timedelta) -> str:
    hours = delta.total_seconds() / 3600
    return f"{hours / 24:.1f} days" if hours >= 48 else f"{hours:.1f} hours"
