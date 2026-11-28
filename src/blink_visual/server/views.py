"""Read models for the dashboard and API (plain dicts, JSON-serializable)."""

from __future__ import annotations

import difflib
import json
from typing import Any
from urllib.parse import urlsplit

from ..alerts import ACTIVE, AlertManager
from ..capture.models import Snapshot, origin_of
from ..errors import BlinkError, StoreError
from ..findings import Severity
from ..inventory import Inventory, entry_for, load_inventory, suggested_id
from ..project import Project
from ..store import Store

HIDDEN_HEADERS = frozenset({"set-cookie", "cookie", "authorization", "proxy-authorization"})
MAX_DIFF_LINES = 400
MAX_LINE = 240
MAX_HAR_ENTRIES = 25
IMAGE_TYPES = frozenset({"image/png"})


def severity_label(value: int | None) -> str | None:
    return None if value is None else Severity(int(value)).label


# -- targets and runs ---------------------------------------------------------------------
def targets_overview(project: Project, store: Store) -> list[dict[str, Any]]:
    baselines = {(b["target"], b["profile"]): b for b in store.baselines()}
    open_alerts: dict[str, int] = {}
    for alert in AlertManager(store).all(ACTIVE):
        open_alerts[alert.target] = open_alerts.get(alert.target, 0) + 1
    rows = []
    for target in project.config.targets:
        profiles = []
        for profile in target.profiles:
            last = store.db.query_one(
                "SELECT r.id, r.finished_at, rr.status, r.max_severity FROM run_results rr "
                "JOIN runs r ON r.id = rr.run_id WHERE rr.target = ? AND rr.profile = ? "
                "AND r.kind = 'scan' ORDER BY r.started_at DESC LIMIT 1",
                (target.name, profile),
            )
            baseline = baselines.get((target.name, profile))
            profiles.append(
                {
                    "profile": profile,
                    "baseline_snapshot": baseline["snapshot_id"] if baseline else None,
                    "baseline_set_at": baseline["set_at"] if baseline else None,
                    "last_run": dict(last) if last else None,
                    "last_severity": severity_label(last["max_severity"]) if last else None,
                }
            )
        rows.append(
            {
                "name": target.name,
                "url": target.url,
                "profiles": profiles,
                "open_alerts": open_alerts.get(target.name, 0),
            }
        )
    return rows


def runs(store: Store, *, limit: int = 200) -> list[dict[str, Any]]:
    rows = store.db.query(
        "SELECT id, kind, started_at, finished_at, status, max_severity FROM runs "
        "ORDER BY started_at DESC, id DESC LIMIT ?",
        (limit,),
    )
    counts: dict[str, dict[str, int]] = {}
    for row in store.db.query(
        "SELECT run_id, severity, COUNT(*) AS n FROM findings GROUP BY run_id, severity"
    ):
        counts.setdefault(row["run_id"], {})[Severity(int(row["severity"])).label] = row["n"]
    return [
        {
            **dict(r),
            "max_severity": severity_label(r["max_severity"]),
            "findings": counts.get(r["id"], {}),
        }
        for r in rows
    ]


def run_detail(store: Store, run_id: str) -> dict[str, Any]:
    run = store.db.query_one("SELECT * FROM runs WHERE id = ?", (run_id,))
    if run is None:
        raise BlinkError(f"unknown run '{run_id}'")
    results = store.db.query(
        "SELECT target, profile, status, baseline_snapshot, current_snapshot, error "
        "FROM run_results WHERE run_id = ? ORDER BY target, profile",
        (run_id,),
    )
    findings = [
        json.loads(r["payload"])
        for r in store.db.query(
            "SELECT payload FROM findings WHERE run_id = ? ORDER BY severity DESC, detector",
            (run_id,),
        )
    ]
    return {
        "run": {**dict(run), "max_severity": severity_label(run["max_severity"])},
        "results": [dict(r) for r in results],
        "findings": findings,
    }


# -- finding detail ------------------------------------------------------------------
def _snapshot(store: Store, snapshot_id: str | None) -> Snapshot | None:
    if not snapshot_id:
        return None
    try:
        return store.load_snapshot(snapshot_id)
    except StoreError:
        return None


def _text_blob(store: Store, digest: str | None) -> str | None:
    if not digest:
        return None
    try:
        return store.get_blob(digest).decode("utf-8", errors="replace")
    except StoreError:
        return None


def _lines(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        if len(line) > 500:  # minified code: break at statement ends to get a useful diff
            out.extend(part + ";" for part in line.split(";"))
        else:
            out.append(line)
    return out


def text_diff(before: str | None, after: str | None) -> list[dict[str, str]] | None:
    if before is None or after is None:
        return None
    diff = difflib.unified_diff(
        _lines(before), _lines(after), "baseline", "current", lineterm="", n=2
    )
    rows: list[dict[str, str]] = []
    for line in diff:
        kind = {"+": "add", "-": "del", "@": "hunk"}.get(line[:1], "ctx")
        if line.startswith(("+++", "---")):
            kind = "file"
        rows.append({"kind": kind, "text": line[:MAX_LINE]})
        if len(rows) >= MAX_DIFF_LINES:
            rows.append({"kind": "hunk", "text": "… diff truncated"})
            break
    return rows


def header_diff(baseline: Snapshot | None, current: Snapshot | None) -> list[dict[str, Any]]:
    before = {k.lower(): v for k, v in (baseline.headers if baseline else {}).items()}
    after = {k.lower(): v for k, v in (current.headers if current else {}).items()}
    rows = []
    for name in sorted(set(before) | set(after)):
        if name in HIDDEN_HEADERS:
            continue
        old, new = before.get(name), after.get(name)
        rows.append({"name": name, "before": old, "after": new, "changed": old != new})
    return rows


def _strip_query(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.scheme else url


def har_excerpt(store: Store, snap: Snapshot | None, subject: str) -> list[dict[str, Any]]:
    if snap is None or "har" not in snap.blobs:
        return []
    try:
        har = json.loads(store.get_blob(snap.blobs["har"]))
    except (StoreError, ValueError):
        return []
    wanted_origin = origin_of(subject) if "://" in subject else None
    wanted_url = _strip_query(subject) if wanted_origin else None
    rows = []
    for entry in har.get("log", {}).get("entries", []):
        request, response = entry.get("request", {}), entry.get("response", {})
        url = str(request.get("url", ""))
        if wanted_origin is not None and origin_of(url) != wanted_origin:
            continue
        rows.append(
            {
                "method": request.get("method"),
                "url": _strip_query(url)[:200],
                "status": response.get("status"),
                "mime": (response.get("content") or {}).get("mimeType"),
                "size": (response.get("content") or {}).get("size"),
                "match": wanted_url is not None and _strip_query(url) == wanted_url,
            }
        )
    rows.sort(key=lambda r: not r["match"])
    return rows[:MAX_HAR_ENTRIES]


def finding_detail(store: Store, run_id: str, fingerprint: str) -> dict[str, Any]:
    row = store.db.query_one(
        "SELECT payload FROM findings WHERE run_id = ? AND (fingerprint = ? OR "
        "substr(fingerprint, 1, 16) = ?)",
        (run_id, fingerprint, fingerprint),
    )
    if row is None:
        raise BlinkError(f"unknown finding '{fingerprint}' in run '{run_id}'")
    finding = json.loads(row["payload"])
    result = store.db.query_one(
        "SELECT baseline_snapshot, current_snapshot FROM run_results WHERE run_id = ? "
        "AND target = ? AND profile = ?",
        (run_id, finding["target"], finding["profile"]),
    )
    baseline = _snapshot(store, result["baseline_snapshot"] if result else None)
    current = _snapshot(store, result["current_snapshot"] if result else None)
    evidence = finding.get("evidence", {})
    images = []
    for label, key in (
        ("Baseline (payment region)", "baseline_blob"),
        ("Current (payment region)", "current_blob"),
        ("Blink overlay", "overlay_blob"),
        ("Blink heatmap", "heatmap_blob"),
        ("Where the journey broke", "screenshot_blob"),
    ):
        if evidence.get(key):
            images.append({"label": label, "blob": evidence[key]})
    if not images:
        for label, snap in (("Baseline", baseline), ("Current", current)):
            if snap is not None:
                blob = snap.blobs.get("region_screenshot") or snap.blobs.get("screenshot")
                if blob:
                    images.append({"label": label, "blob": blob})
    before_text = _text_blob(store, evidence.get("before_blob"))
    after_text = _text_blob(store, evidence.get("after_blob"))
    if finding["detector"] == "inventory" and evidence.get("blob") and baseline is not None:
        old = next((s for s in baseline.scripts if s.key == finding["subject"]), None)
        before_text = _text_blob(store, old.sha256 if old else None)
        after_text = _text_blob(store, evidence.get("blob"))
    alert = store.db.query_one(
        "SELECT id, state FROM alerts WHERE fingerprint = ?", (finding["fingerprint"],)
    )
    return {
        "run_id": run_id,
        "finding": finding,
        "alert": dict(alert) if alert else None,
        "images": images,
        "diff": text_diff(before_text, after_text),
        "headers": header_diff(baseline, current) if finding["detector"] == "headers" else [],
        "har": har_excerpt(store, current, finding["subject"]),
        "baseline_snapshot": baseline.id if baseline else None,
        "current_snapshot": current.id if current else None,
        "static_analysis": evidence.get("static_analysis"),
    }


# -- inventory -----------------------------------------------------------------------
def inventory_rows(project: Project, store: Store) -> list[dict[str, Any]]:
    from ..commands.inventory import collect_scripts

    inventory = load_inventory(project.inventory_path) or Inventory()
    rows: dict[str, dict[str, Any]] = {}
    for entry in inventory.scripts:
        rows[entry.id] = {
            "id": entry.id,
            "listed": True,
            "seen": False,
            "hash_matches": True,
            **entry.model_dump(mode="json"),
            "approved": entry.approved,
            "pinned": entry.pinned,
        }
    if project.config.targets:
        for script, page, where in collect_scripts(project, store, [], None):
            matched = inventory.match(script)
            if matched is not None:
                rows[matched.id]["seen"] = True
                rows[matched.id]["seen_in"] = where
                if matched.pinned and script.sha384 and script.sha384 != matched.expected_hash:
                    rows[matched.id]["hash_matches"] = False
                continue
            draft = entry_for(script, page)
            rows.setdefault(
                suggested_id(script),
                {
                    **draft.model_dump(mode="json"),
                    "listed": False,
                    "seen": True,
                    "seen_in": where,
                    "hash_matches": True,
                    "approved": False,
                    "pinned": draft.pinned,
                },
            )
    return sorted(rows.values(), key=lambda r: (r["approved"], r["type"], r["id"]))


def inventory_row(project: Project, store: Store, entry_id: str) -> dict[str, Any]:
    for row in inventory_rows(project, store):
        if row["id"] == entry_id:
            return row
    raise BlinkError(f"unknown inventory id '{entry_id}'")


# -- settings ------------------------------------------------------------------------
def settings(project: Project) -> dict[str, Any]:
    data = project.config.model_dump(mode="json", by_alias=True, exclude_none=True)
    for sink in data.get("alerts", {}).get("sinks", []):
        if "url" in sink:
            sink["url"] = "[redacted: webhook URLs are secrets]"
    return data


def blob_media_type(store: Store, digest: str) -> str | None:
    row = store.db.query_one("SELECT media_type FROM blobs WHERE sha256 = ?", (digest,))
    return None if row is None else str(row["media_type"])
