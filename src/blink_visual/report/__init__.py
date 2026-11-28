"""``blink report``: an audit evidence pack for PCI DSS 6.4.3 and 11.6.1.

One evidence model (a JSON-serializable dict) feeds the HTML page, the PDF and the signed
``report.json`` sidecar, so the three always say the same thing.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from itertools import pairwise
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from ..alerts import ACCEPTED, RESOLVED
from ..errors import BlinkError, StoreError
from ..findings import Severity
from ..inventory import Inventory, load_inventory, suggested_id
from ..project import Project
from ..scan import blink_version
from ..schedule import WEEK, max_gap
from ..store import Store
from ..store.ledger import (
    canonical,
    key_fingerprint,
    key_path,
    load_private_key,
    load_public_key,
    public_key_text,
)

SCHEMA = "blink.report.v1"
DEFAULT_DAYS = 90
SIGNATURE_ALGORITHM = "ed25519"
PCI_LIBRARY = "https://www.pcisecuritystandards.org/document_library/"

DISCLAIMER = (
    "This report is evidence produced by an automated monitoring tool. It supports, but does "
    "not replace, the judgment of a Qualified Security Assessor or internal auditor, who "
    "decides whether PCI DSS requirements 6.4.3 and 11.6.1 are met. Blink observes the pages "
    "it is configured to load, from where it runs; it cannot attest to what other visitors "
    "received."
)
METHODOLOGY = (
    "Each evaluation loads the configured payment page in headless Chromium for every "
    "configured browser profile, records every script (external, inline and in frames) with "
    "its SHA-384 and SHA-256 digests, the response headers including Content-Security-Policy, "
    "the payment-form DOM, network destinations and a screenshot of the payment region.",
    "Each evaluation is compared with an approved baseline. Detectors report added, removed "
    "and changed scripts, unapproved scripts (against blink.inventory.yaml), security-header "
    "and CSP changes, new network destinations, payment-form changes and visual changes. A "
    "rule engine assigns each finding a severity.",
    "New and changed scripts get a static-analysis risk score (0–100) that explains which "
    "skimmer-like patterns it found.",
    "Runs, baselines, approvals and alert decisions are appended to a hash-chained ledger "
    "whose head is signed with an ed25519 key, so later edits to the history are detectable.",
)
LIMITATIONS = (
    "Monitoring is from one vantage point. Scripts served conditionally (by geography, user "
    "agent, cookie or time) may not be seen.",
    "Scripts marked 'dynamic' are not pinned to a hash. Their changes are reported for review "
    "rather than blocked, and the static-analysis score is a triage aid a careful attacker "
    "can evade.",
    "Blink detects changes; it does not prevent them. Prevention relies on the site's own "
    "CSP and Subresource Integrity.",
    "The ledger proves history was not edited without the signing key. Someone holding the "
    "key and write access to the store could rewrite it. Pin the public key elsewhere and "
    "keep exported reports.",
)


@dataclass(frozen=True)
class Period:
    start: datetime
    end: datetime

    @classmethod
    def last(cls, days: int, *, now: datetime) -> Period:
        return cls(now - timedelta(days=days), now)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _hours(delta: timedelta) -> float:
    return round(delta.total_seconds() / 3600, 2)


def _label(value: int | None) -> str | None:
    return None if value is None else Severity(int(value)).label


# -- sections ---------------------------------------------------------------------------
def _scope(project: Project, store: Store, now: datetime) -> dict[str, Any]:
    baselines = {(b["target"], b["profile"]): b for b in store.baselines()}
    targets = []
    for target in project.config.targets:
        schedule = project.config.schedule_for(target)
        targets.append(
            {
                "name": target.name,
                "url": target.url,
                "profiles": list(target.profiles),
                "schedule": {"interval": schedule.interval, "cron": schedule.cron},
                "max_gap_hours": _hours(max_gap(schedule, now=now)),
                "baselines": [
                    {
                        "profile": profile,
                        "snapshot_id": baselines[(target.name, profile)]["snapshot_id"],
                        "set_at": baselines[(target.name, profile)]["set_at"],
                        "reason": baselines[(target.name, profile)].get("reason", ""),
                    }
                    for profile in target.profiles
                    if (target.name, profile) in baselines
                ],
            }
        )
    return {"config": project.config_path.name, "targets": targets}


def _approval_records(store: Store) -> dict[str, dict[str, Any]]:
    """The latest ``inventory.approved`` ledger record for each inventory id."""
    out: dict[str, dict[str, Any]] = {}
    for record in store.ledger.records({"inventory.approved"}):
        entry_id = record.payload.get("id")
        if isinstance(entry_id, str):
            out[entry_id] = {"seq": record.seq, "at": record.at}
    return out


def _inventory(project: Project, store: Store) -> dict[str, Any]:
    from ..commands.inventory import collect_scripts

    inventory = load_inventory(project.inventory_path) or Inventory()
    ledgered = _approval_records(store)
    entries = []
    for entry in inventory.scripts:
        record = ledgered.get(entry.id)
        if not entry.approved:
            authorization = "not approved"
        elif record is not None:
            authorization = (
                f"approved by {entry.approved_by} on {entry.approved_at} in "
                f"{project.inventory_path.name}; ledger record #{record['seq']}"
            )
        else:
            authorization = (
                f"approved by {entry.approved_by} on {entry.approved_at} in "
                f"{project.inventory_path.name} (edited by hand; no ledger record)"
            )
        if entry.pinned:
            integrity = f"pinned {entry.expected_hash[:20]}…"
        else:
            integrity = "dynamic (changes are reported for review)"
        entries.append(
            {
                "id": entry.id,
                "type": entry.type,
                "source": entry.url or entry.url_pattern or entry.inline_sha384 or "",
                "justification": entry.justification,
                "owner": entry.owner,
                "approved": entry.approved,
                "approved_by": entry.approved_by or None,
                "approved_at": entry.approved_at,
                "authorization": authorization,
                "ledger_seq": record["seq"] if record else None,
                "integrity": integrity,
                "pinned": entry.pinned,
                "sri": bool(entry.sri),
            }
        )
    unlisted: dict[str, dict[str, Any]] = {}
    if project.config.targets:
        for script, _page, where in collect_scripts(project, store, [], None):
            if inventory.match(script) is None:
                unlisted.setdefault(
                    suggested_id(script),
                    {"id": suggested_id(script), "source": script.key, "seen_in": where},
                )
    approved = [e for e in entries if e["approved"]]
    return {
        "path": project.inventory_path.name,
        "entries": entries,
        "unlisted": sorted(unlisted.values(), key=lambda u: u["id"]),
        "summary": {
            "total": len(entries),
            "approved": len(approved),
            "unapproved": len(entries) - len(approved) + len(unlisted),
            "pinned": sum(1 for e in approved if e["pinned"]),
            "dynamic": sum(1 for e in approved if not e["pinned"]),
            "with_sri": sum(1 for e in entries if e["sri"]),
        },
    }


def _integrity(inventory: dict[str, Any]) -> dict[str, Any]:
    summary = inventory["summary"]
    return {
        "method": [
            "Every script body observed in an evaluation is hashed with SHA-384 (the Subresource "
            "Integrity algorithm) and SHA-256 (the content-addressed evidence store).",
            "Approved scripts are either pinned (any change to their SHA-384 is a critical "
            "finding) or dynamic (changes are reported for review with a static-analysis score).",
            "Inline scripts are identified by their SHA-384, so any edit makes them a new, "
            "unapproved script.",
            "Where the page uses Subresource Integrity, the integrity attribute is recorded and "
            "its removal or change is reported.",
        ],
        "pinned": summary["pinned"],
        "dynamic": summary["dynamic"],
        "with_sri": summary["with_sri"],
    }


def _evaluations(project: Project, store: Store, period: Period) -> dict[str, Any]:
    rows = store.db.query(
        "SELECT r.id, r.finished_at, r.max_severity, rr.target, rr.profile, rr.status, "
        "rr.error FROM run_results rr JOIN runs r ON r.id = rr.run_id "
        "WHERE r.kind = 'scan' AND r.finished_at >= ? AND r.finished_at <= ? "
        "ORDER BY r.finished_at, r.id",
        (_iso(period.start), _iso(period.end)),
    )
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        by_pair.setdefault((row["target"], row["profile"]), []).append(
            {
                "run_id": row["id"],
                "at": row["finished_at"],
                "status": row["status"],
                "max_severity": _label(row["max_severity"]),
                "error": row["error"],
            }
        )
    out = []
    worst: timedelta | None = None
    for target in project.config.targets:
        allowed = max_gap(project.config.schedule_for(target), now=period.end)
        for profile in target.profiles:
            runs = by_pair.get((target.name, profile), [])
            ok_times = [_parse(r["at"]) for r in runs if r["status"] == "ok"]
            if ok_times:
                gaps = [b - a for a, b in pairwise(ok_times)] + [period.end - ok_times[-1]]
                gap: timedelta | None = max(gaps)
            else:
                gap = None
            if gap is not None and (worst is None or gap > worst):
                worst = gap
            out.append(
                {
                    "target": target.name,
                    "profile": profile,
                    "evaluations": len(ok_times),
                    "failed": sum(1 for r in runs if r["status"] != "ok"),
                    "first": runs[0]["at"] if runs else None,
                    "last": runs[-1]["at"] if runs else None,
                    "max_gap_hours": None if gap is None else _hours(gap),
                    "allowed_gap_hours": _hours(allowed),
                    "within_schedule": gap is not None and gap <= allowed,
                    "weekly": gap is not None and gap <= WEEK,
                    "runs": runs,
                }
            )
    return {
        "targets": out,
        "max_gap_hours": None if worst is None else _hours(worst),
        "weekly": bool(out) and all(t["weekly"] for t in out),
        "note": (
            "The maximum gap is the longest time between two successful evaluations in the "
            "period, including the time from the last one to the end of the period."
        ),
    }


def _findings(store: Store, period: Period) -> dict[str, Any]:
    import json

    rows = store.db.query(
        "SELECT f.fingerprint, f.severity, f.payload, r.finished_at, r.id AS run_id "
        "FROM findings f JOIN runs r ON r.id = f.run_id "
        "WHERE r.finished_at >= ? AND r.finished_at <= ? ORDER BY r.finished_at",
        (_iso(period.start), _iso(period.end)),
    )
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = json.loads(row["payload"])
        item = grouped.setdefault(
            row["fingerprint"],
            {
                "id": payload["id"],
                "fingerprint": row["fingerprint"],
                "first_seen": row["finished_at"],
                "first_run_id": row["run_id"],
                "occurrences": 0,
                "severity_value": 0,
            },
        )
        item.update(
            {
                "title": payload["title"],
                "detector": payload["detector"],
                "change_type": payload["change_type"],
                "target": payload["target"],
                "profile": payload["profile"],
                "rule_id": payload.get("rule_id"),
                "last_seen": row["finished_at"],
            }
        )
        item["occurrences"] += 1
        item["severity_value"] = max(item["severity_value"], int(row["severity"]))
    items = []
    for item in grouped.values():
        alert = store.db.query_one(
            "SELECT id, state, updated_at, updated_by, note FROM alerts WHERE fingerprint = ?",
            (item["fingerprint"],),
        )
        events = [
            dict(e)
            for e in store.db.query(
                "SELECT at, from_state, to_state, actor, note FROM alert_events "
                "WHERE fingerprint = ? ORDER BY id",
                (item["fingerprint"],),
            )
        ]
        resolution = None
        for event in reversed(events):
            if event["to_state"] in (RESOLVED, ACCEPTED):
                resolution = {
                    "state": event["to_state"],
                    "by": event["actor"],
                    "at": event["at"],
                    "note": event["note"],
                }
                break
        item.update(
            severity=Severity(item.pop("severity_value")).label,
            state=alert["state"] if alert else "untracked",
            resolution=resolution,
            events=events,
        )
        items.append(item)
    items.sort(key=lambda i: (-Severity.parse(i["severity"]).value, i["first_seen"]))
    summary: dict[str, int] = {}
    for item in items:
        summary[item["severity"]] = summary.get(item["severity"], 0) + 1
    unresolved = [i for i in items if i["state"] in ("open", "acknowledged")]
    return {"summary": summary, "unresolved": len(unresolved), "items": items}


def _ledger(store: Store, public_key: str | None) -> dict[str, Any]:
    verification = store.ledger.verify(public_key=public_key)
    head = store.db.query_one("SELECT seq, hash, signature, signed_at FROM ledger_head")
    return {
        **verification.to_dict(),
        "public_key": verification.public_key,
        "key_pinned": public_key is not None,
        "head": dict(head) if head else None,
    }


def build_report(
    project: Project,
    store: Store,
    *,
    period: Period,
    now: datetime | None = None,
    public_key: str | None = None,
) -> dict[str, Any]:
    if period.start >= period.end:
        raise BlinkError("the report period must start before it ends")
    moment = now or datetime.now(UTC)
    inventory = _inventory(project, store)
    return {
        "schema": SCHEMA,
        "generated_at": _iso(moment),
        "blink_version": blink_version(),
        "period": {"from": _iso(period.start), "to": _iso(period.end)},
        "scope": _scope(project, store, moment),
        "inventory": inventory,
        "integrity": _integrity(inventory),
        "evaluations": _evaluations(project, store, period),
        "findings": _findings(store, period),
        "ledger": _ledger(store, public_key),
        "methodology": list(METHODOLOGY),
        "limitations": list(LIMITATIONS),
        "disclaimer": DISCLAIMER,
        "references": {"pci_ssc_document_library": PCI_LIBRARY},
    }


# -- rendering -------------------------------------------------------------------------
def render_html(report: dict[str, Any]) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(files("blink_visual.report") / "templates")),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template("report.html").render(r=report)


def render_pdf(html: str) -> bytes:
    """Print the HTML with headless Chromium (JavaScript off; the page has none)."""
    from ..capture.browser import Capturer

    with Capturer() as capturer:
        context = capturer.browser.new_context(java_script_enabled=False, offline=True)
        try:
            page = context.new_page()
            page.set_content(html, wait_until="load")
            return page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "16mm", "bottom": "16mm", "left": "14mm", "right": "14mm"},
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=(
                    '<div style="font-size:8px;width:100%;text-align:center;color:#666">'
                    'Blink audit evidence · page <span class="pageNumber"></span> of '
                    '<span class="totalPages"></span></div>'
                ),
            )
        finally:
            context.close()


# -- signing ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sign_report(
    report: dict[str, Any], store_dir: Path, artifacts: dict[str, str]
) -> dict[str, Any]:
    """Return the sidecar: the report, the artifact hashes and an ed25519 signature."""
    body = {**report, "artifacts": artifacts}
    path = key_path(store_dir)
    if not path.exists():
        raise BlinkError(
            f"the signing key {path} is missing",
            hint="run `blink init` to create it, or restore it from backup",
        )
    key = load_private_key(path)
    public = public_key_text(key.public_key())
    signature = base64.b64encode(key.sign(canonical(body))).decode("ascii")
    return {
        **body,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "public_key": public,
            "public_key_fingerprint": key_fingerprint(public),
            "value": signature,
            "signed": "canonical JSON of this document without the 'signature' member",
        },
    }


@dataclass(frozen=True)
class SidecarCheck:
    ok: bool
    problems: tuple[str, ...]
    fingerprint: str | None


def verify_sidecar(
    sidecar: dict[str, Any], *, directory: Path | None = None, public_key: str | None = None
) -> SidecarCheck:
    """Check the signature and, if ``directory`` is given, the artifact hashes.

    Without ``public_key`` only the embedded key is used, which proves integrity but not who
    signed it; pass the pinned ledger public key to prove origin too.
    """
    problems: list[str] = []
    body = dict(sidecar)
    signature = body.pop("signature", None)
    if not isinstance(signature, dict) or signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return SidecarCheck(False, ("the report has no ed25519 signature",), None)
    embedded = str(signature.get("public_key", ""))
    expected = public_key or embedded
    if public_key is not None and embedded != public_key:
        problems.append("the report was signed with a different key than expected")
    try:
        load_public_key(expected).verify(
            base64.b64decode(str(signature.get("value", ""))), canonical(body)
        )
    except InvalidSignature:
        problems.append("the report signature is invalid (the report was modified)")
    except (ValueError, StoreError):
        problems.append("the report signature or public key is malformed")
    if directory is not None:
        for name, digest in dict(body.get("artifacts", {})).items():
            path = directory / name
            if not path.exists():
                problems.append(f"{name} is missing")
            elif sha256_file(path) != digest:
                problems.append(f"{name} does not match the signed hash (it was modified)")
    return SidecarCheck(
        not problems, tuple(problems), key_fingerprint(expected) if expected else None
    )
