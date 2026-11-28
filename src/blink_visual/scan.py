"""Baselines and scans: capture, compare with the baseline, grade and persist findings."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .capture.browser import Capturer, new_snapshot_id
from .capture.models import Snapshot
from .config import TargetConfig
from .detect import DetectionContext, run_detectors
from .errors import EXIT_CAPTURE, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, CaptureError
from .findings import Finding, Severity
from .project import Project
from .rules import RuleEngine
from .store import Store, utc_now

REPORT_SCHEMA_VERSION = 2

STATUS_OK = "ok"
STATUS_NO_BASELINE = "no_baseline"
STATUS_CAPTURE_FAILED = "capture_failed"


def blink_version() -> str:
    try:
        return version("blink-visual")
    except PackageNotFoundError:  # pragma: no cover - running from a source tree
        return "unknown"


@dataclass(frozen=True)
class TargetResult:
    target: str
    profile: str
    status: str
    baseline_snapshot: str | None = None
    current_snapshot: str | None = None
    error: str | None = None
    findings: int = 0


@dataclass(frozen=True)
class ScanReport:
    run_id: str
    started_at: str
    finished_at: str
    fail_on: Severity | None
    results: tuple[TargetResult, ...]
    findings: tuple[Finding, ...]
    blink_version: str = field(default_factory=blink_version)

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    @property
    def gate_failed(self) -> bool:
        return self.fail_on is not None and any(f.severity >= self.fail_on for f in self.findings)

    @property
    def exit_code(self) -> int:
        statuses = {r.status for r in self.results}
        if STATUS_CAPTURE_FAILED in statuses:
            return EXIT_CAPTURE
        if STATUS_NO_BASELINE in statuses:
            return EXIT_USAGE
        return EXIT_FINDINGS if self.gate_failed else EXIT_OK

    def to_dict(self) -> dict[str, Any]:
        counts = Counter(f.severity.label for f in self.findings)
        statuses = Counter(r.status for r in self.results)
        gate = "skipped" if self.fail_on is None else ("failed" if self.gate_failed else "passed")
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "kind": "blink.scan",
            "run_id": self.run_id,
            "blink_version": self.blink_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "fail_on": None if self.fail_on is None else self.fail_on.label,
            "gate": gate,
            "summary": {
                "findings": len(self.findings),
                "by_severity": {s.label: counts.get(s.label, 0) for s in Severity},
                "max_severity": None if self.max_severity is None else self.max_severity.label,
                "targets": len(self.results),
                "capture_failed": statuses.get(STATUS_CAPTURE_FAILED, 0),
                "no_baseline": statuses.get(STATUS_NO_BASELINE, 0),
            },
            "targets": [
                {
                    "target": r.target,
                    "profile": r.profile,
                    "status": r.status,
                    "baseline_snapshot": r.baseline_snapshot,
                    "current_snapshot": r.current_snapshot,
                    "error": r.error,
                    "findings": r.findings,
                }
                for r in self.results
            ],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, allow_nan=False) + "\n"


def _profiles(target: TargetConfig, profiles: Sequence[str] | None) -> list[str]:
    return [p for p in target.profiles if p in profiles] if profiles else list(target.profiles)


def establish_baseline(
    project: Project,
    store: Store,
    target: TargetConfig,
    capturer: Capturer,
    *,
    profiles: Sequence[str] | None = None,
    reason: str = "",
) -> list[Snapshot]:
    """Capture ``target`` and mark each snapshot as the known-good baseline."""
    snapshots: list[Snapshot] = []
    for name in _profiles(target, profiles):
        snapshot = capturer.capture(target, name, project.config.profile(name), store)
        store.save_snapshot(snapshot)
        store.set_baseline(target.name, name, snapshot.id, reason=reason)
        snapshots.append(snapshot)
    return snapshots


def compare_snapshots(
    project: Project,
    store: Store,
    target: TargetConfig,
    baseline: Snapshot,
    current: Snapshot,
    *,
    engine: RuleEngine | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    ctx = DetectionContext(
        baseline=baseline,
        current=current,
        target=target,
        store=store,
        now=now or datetime.now(UTC),
    )
    engine = engine or rule_engine(project)
    graded = engine.grade_all(run_detectors(ctx))
    return sorted(graded, key=lambda f: (-f.severity, f.detector, f.change_type, f.subject))


def rule_engine(project: Project) -> RuleEngine:
    path = project.root / project.config.rules if project.config.rules else None
    return RuleEngine.for_file(path)


def scan(
    project: Project,
    store: Store,
    targets: Sequence[TargetConfig],
    capturer: Capturer,
    *,
    profiles: Sequence[str] | None = None,
    fail_on: Severity | None = Severity.HIGH,
    now: datetime | None = None,
) -> ScanReport:
    """Capture every target/profile, compare with its baseline and record the run."""
    started = datetime.now(UTC)
    engine = rule_engine(project)
    results: list[TargetResult] = []
    findings: list[Finding] = []
    for target in targets:
        for name in _profiles(target, profiles):
            baseline_id = store.baseline_id(target.name, name)
            try:
                current = capturer.capture(target, name, project.config.profile(name), store)
            except CaptureError as exc:
                results.append(
                    TargetResult(
                        target.name, name, STATUS_CAPTURE_FAILED, baseline_id, None, str(exc)
                    )
                )
                continue
            store.save_snapshot(current)
            if baseline_id is None:
                results.append(
                    TargetResult(
                        target.name,
                        name,
                        STATUS_NO_BASELINE,
                        None,
                        current.id,
                        f"no baseline for {target.name} [{name}]; "
                        f"run `blink baseline {target.name}`",
                    )
                )
                continue
            baseline = store.load_snapshot(baseline_id)
            found = compare_snapshots(
                project, store, target, baseline, current, engine=engine, now=now
            )
            findings.extend(found)
            results.append(
                TargetResult(
                    target.name, name, STATUS_OK, baseline_id, current.id, None, len(found)
                )
            )
    finished = datetime.now(UTC)
    report = ScanReport(
        run_id=f"run-{new_snapshot_id(started)}",
        started_at=_iso(started),
        finished_at=_iso(finished),
        fail_on=fail_on,
        results=tuple(results),
        findings=tuple(findings),
    )
    store.record_scan(report)
    return report


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


__all__ = [
    "ScanReport",
    "TargetResult",
    "compare_snapshots",
    "establish_baseline",
    "scan",
    "utc_now",
]
