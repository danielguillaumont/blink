"""Alert state machine: ``open → acknowledged → resolved | accepted-change``.

Findings become alerts keyed by their fingerprint, so the same problem seen on every scan is
one alert (deduplicated), not one notification per run. A resolved or accepted alert whose
finding comes back is reopened. Every transition is recorded in ``alert_events`` and in the
tamper-evident ledger. Accepting a change rebaselines the target/profile from the run that
last saw the finding and records who accepted it and why.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..errors import BlinkError
from ..findings import Finding, Severity
from ..store import Store, utc_now

OPEN = "open"
ACKNOWLEDGED = "acknowledged"
RESOLVED = "resolved"
ACCEPTED = "accepted-change"
STATES = (OPEN, ACKNOWLEDGED, RESOLVED, ACCEPTED)
TRANSITIONS: dict[str, frozenset[str]] = {
    OPEN: frozenset({ACKNOWLEDGED, RESOLVED, ACCEPTED}),
    ACKNOWLEDGED: frozenset({RESOLVED, ACCEPTED}),
    RESOLVED: frozenset({OPEN}),
    ACCEPTED: frozenset({OPEN}),
}
ACTIVE = frozenset({OPEN, ACKNOWLEDGED})
SYSTEM = "blink"


@dataclass(frozen=True)
class Alert:
    id: str
    fingerprint: str
    target: str
    profile: str
    detector: str
    change_type: str
    subject: str
    title: str
    why: str
    severity: Severity
    state: str
    first_seen_at: str
    last_seen_at: str
    first_run_id: str
    last_run_id: str
    occurrences: int
    updated_at: str
    updated_by: str
    note: str

    @classmethod
    def from_row(cls, row: Any) -> Alert:
        data = dict(row)
        data["severity"] = Severity(int(data["severity"]))
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["severity"] = self.severity.label
        return data


@dataclass(frozen=True)
class Notification:
    """What a sink delivers. Contains no evidence blobs, cookies, headers or secrets."""

    event: str  # opened | reopened | escalated
    alert: Alert
    run_id: str

    def to_dict(self) -> dict[str, Any]:
        a = self.alert
        return {
            "schema": "blink.alert.v1",
            "event": self.event,
            "run_id": self.run_id,
            "alert_id": a.id,
            "fingerprint": a.fingerprint,
            "state": a.state,
            "severity": a.severity.label,
            "target": a.target,
            "profile": a.profile,
            "detector": a.detector,
            "change_type": a.change_type,
            "subject": a.subject,
            "title": a.title,
            "why": a.why,
            "first_seen_at": a.first_seen_at,
            "last_seen_at": a.last_seen_at,
            "occurrences": a.occurrences,
        }


class AlertManager:
    def __init__(self, store: Store) -> None:
        self.store = store

    # -- queries -------------------------------------------------------------------
    def get(self, alert_id: str) -> Alert:
        row = self.store.db.query_one(
            "SELECT * FROM alerts WHERE id = ? OR fingerprint = ?", (alert_id, alert_id)
        )
        if row is None:
            raise BlinkError(f"unknown alert '{alert_id}'", hint="list alerts with `blink alerts`")
        return Alert.from_row(row)

    def all(self, states: Iterable[str] | None = None) -> list[Alert]:
        wanted = set(states or STATES)
        rows = self.store.db.query("SELECT * FROM alerts ORDER BY severity DESC, last_seen_at DESC")
        return [Alert.from_row(r) for r in rows if r["state"] in wanted]

    def events(self, alert_id: str) -> list[dict[str, Any]]:
        alert = self.get(alert_id)
        rows = self.store.db.query(
            "SELECT at, from_state, to_state, actor, note, run_id FROM alert_events "
            "WHERE fingerprint = ? ORDER BY id",
            (alert.fingerprint,),
        )
        return [dict(r) for r in rows]

    # -- ingestion -----------------------------------------------------------------
    def ingest(
        self, run_id: str, findings: Iterable[Finding], *, at: str | None = None
    ) -> list[Notification]:
        """Create or update alerts for a run's findings; return what needs notifying."""
        moment = at or utc_now()
        notifications: list[Notification] = []
        for finding in findings:
            event = self._ingest_one(run_id, finding, moment)
            if event is not None:
                notifications.append(Notification(event, self.get(finding.fingerprint), run_id))
        return notifications

    def _ingest_one(self, run_id: str, f: Finding, at: str) -> str | None:
        existing = self.store.db.query_one(
            "SELECT state, severity FROM alerts WHERE fingerprint = ?", (f.fingerprint,)
        )
        if existing is None:
            with self.store.db.transaction() as conn:
                conn.execute(
                    "INSERT INTO alerts (fingerprint, id, target, profile, detector, change_type, "
                    "subject, title, why, severity, state, first_seen_at, last_seen_at, "
                    "first_run_id, last_run_id, occurrences, updated_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                    (
                        f.fingerprint,
                        f.id,
                        f.target,
                        f.profile,
                        f.detector,
                        f.change_type,
                        f.subject,
                        f.title,
                        f.why,
                        int(f.severity),
                        OPEN,
                        at,
                        at,
                        run_id,
                        run_id,
                        at,
                        SYSTEM,
                    ),
                )
                self._event(conn, f.fingerprint, at, None, OPEN, SYSTEM, "", run_id)
            self._ledger("alert.opened", f.fingerprint, None, OPEN, SYSTEM, "", run_id, at)
            return "opened"
        state, severity = str(existing["state"]), Severity(int(existing["severity"]))
        reopen = state not in ACTIVE
        escalated = f.severity > severity
        with self.store.db.transaction() as conn:
            conn.execute(
                "UPDATE alerts SET last_seen_at = ?, last_run_id = ?, "
                "occurrences = occurrences + 1, severity = MAX(severity, ?), title = ?, why = ? "
                "WHERE fingerprint = ?",
                (at, run_id, int(f.severity), f.title, f.why, f.fingerprint),
            )
            if reopen:
                conn.execute(
                    "UPDATE alerts SET state = ?, updated_at = ?, updated_by = ?, note = '' "
                    "WHERE fingerprint = ?",
                    (OPEN, at, SYSTEM, f.fingerprint),
                )
                self._event(conn, f.fingerprint, at, state, OPEN, SYSTEM, "seen again", run_id)
        if reopen:
            self._ledger("alert.reopened", f.fingerprint, state, OPEN, SYSTEM, "", run_id, at)
            return "reopened"
        return "escalated" if escalated else None

    # -- transitions -----------------------------------------------------------------
    def transition(self, alert_id: str, to_state: str, *, actor: str, note: str = "") -> Alert:
        if to_state not in STATES:
            raise BlinkError(f"unknown alert state '{to_state}'")
        alert = self.get(alert_id)
        if to_state not in TRANSITIONS[alert.state]:
            allowed = ", ".join(sorted(TRANSITIONS[alert.state])) or "none"
            raise BlinkError(
                f"alert {alert.id} is {alert.state}; it cannot become {to_state}",
                hint=f"allowed next states: {allowed}",
            )
        if not actor.strip():
            raise BlinkError("an actor is required for alert state changes (--by)")
        if to_state == ACCEPTED and not note.strip():
            raise BlinkError("accepting a change needs a reason (--note)")
        at = utc_now()
        if to_state == ACCEPTED:
            self._rebaseline(alert, actor=actor, note=note)
        with self.store.db.transaction() as conn:
            conn.execute(
                "UPDATE alerts SET state = ?, updated_at = ?, updated_by = ?, note = ? "
                "WHERE fingerprint = ?",
                (to_state, at, actor.strip(), note.strip(), alert.fingerprint),
            )
            self._event(conn, alert.fingerprint, at, alert.state, to_state, actor, note, None)
        self._ledger(
            f"alert.{to_state}", alert.fingerprint, alert.state, to_state, actor, note, None, at
        )
        return self.get(alert.fingerprint)

    def _rebaseline(self, alert: Alert, *, actor: str, note: str) -> None:
        row = self.store.db.query_one(
            "SELECT current_snapshot FROM run_results WHERE run_id = ? AND target = ? "
            "AND profile = ?",
            (alert.last_run_id, alert.target, alert.profile),
        )
        snapshot = None if row is None else row["current_snapshot"]
        if snapshot is None:
            if alert.detector == "schedule":
                return  # schedule findings have no snapshot to accept
            raise BlinkError(
                f"run {alert.last_run_id} has no snapshot for {alert.target} [{alert.profile}]"
            )
        self.store.set_baseline(
            alert.target,
            alert.profile,
            snapshot,
            reason=f"accepted change for alert {alert.id} by {actor.strip()}: {note.strip()}",
        )

    # -- helpers -----------------------------------------------------------------------
    @staticmethod
    def _event(
        conn: Any,
        fingerprint: str,
        at: str,
        from_state: str | None,
        to_state: str,
        actor: str,
        note: str,
        run_id: str | None,
    ) -> None:
        conn.execute(
            "INSERT INTO alert_events (fingerprint, at, from_state, to_state, actor, note, "
            "run_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (fingerprint, at, from_state, to_state, actor.strip(), note.strip(), run_id),
        )

    def _ledger(
        self,
        kind: str,
        fingerprint: str,
        from_state: str | None,
        to_state: str,
        actor: str,
        note: str,
        run_id: str | None,
        at: str,
    ) -> None:
        self.store.ledger.append(
            kind,
            {
                "alert": fingerprint[:16],
                "fingerprint": fingerprint,
                "from": from_state,
                "to": to_state,
                "actor": actor.strip(),
                "note": note.strip(),
                "run_id": run_id,
            },
            at=at,
        )


__all__ = [
    "ACCEPTED",
    "ACKNOWLEDGED",
    "OPEN",
    "RESOLVED",
    "STATES",
    "TRANSITIONS",
    "Alert",
    "AlertManager",
    "Notification",
]
