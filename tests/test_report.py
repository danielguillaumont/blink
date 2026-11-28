"""``blink report``: the audit evidence report (HTML, PDF, signed report.json)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from helpers import snapshot

from blink_visual.alerts import RESOLVED, AlertManager
from blink_visual.capture.models import ScriptRecord
from blink_visual.cli import main
from blink_visual.commands.inventory import approve_entries
from blink_visual.findings import Severity
from blink_visual.project import Project
from blink_visual.report import (
    DISCLAIMER,
    Period,
    build_report,
    render_html,
    sign_report,
    verify_sidecar,
)
from blink_visual.scan import ScanReport, TargetResult, _record, compare_snapshots
from blink_visual.store.ledger import key_path

PAGE = "https://shop.example/checkout"
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
SNAPSHOTS = Path(__file__).parent / "snapshots"


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _script(store, body: bytes) -> ScriptRecord:
    import base64
    import hashlib

    return ScriptRecord(
        url=f"{PAGE}/app.js",
        inline=False,
        frame_url=PAGE,
        sha384="sha384-" + base64.b64encode(hashlib.sha384(body).digest()).decode(),
        sha256=store.put_blob(body, "text/javascript"),
        size=len(body),
    )


def _scan(project, store, run_id, at, base, current, status="ok"):
    findings = (
        compare_snapshots(project, store, project.config.targets[0], base, current)
        if status == "ok"
        else []
    )
    report = ScanReport(
        run_id=run_id,
        started_at=_iso(at - timedelta(seconds=5)),
        finished_at=_iso(at),
        fail_on=Severity.HIGH,
        results=(
            TargetResult(
                "checkout",
                "desktop-chrome",
                status,
                base.id,
                current.id if status == "ok" else None,
                None if status == "ok" else "timeout",
                len(findings),
            ),
        ),
        findings=tuple(findings),
    )
    _record(store, report, kind="scan")


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = {"targets": [{"name": "checkout", "url": PAGE}], "schedule": {"interval": "1d"}}
    (tmp_path / "blink.yaml").write_text(yaml.safe_dump(config), "utf-8")
    project = Project.load(tmp_path / "blink.yaml")
    with project.open_store() as store:
        store.ensure_target("checkout", PAGE)
        base = snapshot(
            id="snap-base", target="checkout", scripts=(_script(store, b"var a = 1;\n"),)
        )
        changed = replace(base, id="snap-changed", scripts=(_script(store, b"var a = 2;\n"),))
        store.save_snapshot(base)
        store.save_snapshot(changed)
        store.set_baseline("checkout", "desktop-chrome", base.id)
        # 2026-11-01 clean, 11-04 changed, 11-05 failed capture, 11-14 changed again (gap 10d).
        _scan(project, store, "run-1", datetime(2026, 11, 1, tzinfo=UTC), base, base)
        _scan(project, store, "run-2", datetime(2026, 11, 4, tzinfo=UTC), base, changed)
        _scan(
            project,
            store,
            "run-3",
            datetime(2026, 11, 5, tzinfo=UTC),
            base,
            changed,
            status="failed",
        )
        _scan(project, store, "run-4", datetime(2026, 11, 14, tzinfo=UTC), base, changed)
        _scan(project, store, "run-old", datetime(2026, 6, 1, tzinfo=UTC), base, changed)
        manager = AlertManager(store)
        alert = manager.all()[0]
        manager.transition(alert.id, RESOLVED, actor="dana", note="CHG-42 reviewed")
    (entry,) = _inventory_ids(project)
    approve_entries(project, [entry], justification="Checkout UI", owner="web", approved_by="erin")
    return project


def _inventory_ids(project) -> list[str]:
    from blink_visual.commands.inventory import collect_scripts
    from blink_visual.inventory import suggested_id

    with project.open_store() as store:
        return sorted({suggested_id(s) for s, _p, _w in collect_scripts(project, store, [], None)})


def _report(project, **kwargs):
    with project.open_store() as store:
        return build_report(
            project,
            store,
            period=Period(datetime(2026, 10, 28, tzinfo=UTC), NOW),
            now=NOW,
            **kwargs,
        )


def _shape(value):
    """The key structure of a JSON value: dict keys recursively, lists by their first item."""
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_shape(value[0])] if value else []
    return type(value).__name__ if value is not None else "null"


def _html_outline(html: str) -> list[str]:
    sections = re.findall(r'<section id="([a-z-]+)">\s*<h2>([^<]+)</h2>', html)
    return [f"{sid}: {title}" for sid, title in sections]


# --- structure ------------------------------------------------------------------------


def test_report_structure_snapshot(project):
    """Snapshot of the report's structure (sections and keys, not values).

    Regenerate with BLINK_UPDATE_SNAPSHOTS=1 after an intentional change.
    """
    report = _report(project)
    html = render_html(report)
    actual = {
        "sections": list(report),
        "html_outline": _html_outline(html),
        "shape": _shape(report),
    }
    path = SNAPSHOTS / "report_structure.json"
    if os.environ.get("BLINK_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_bytes((json.dumps(actual, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    assert path.exists(), "missing snapshot; run with BLINK_UPDATE_SNAPSHOTS=1"
    expected = json.loads(path.read_text("utf-8"))
    assert actual == expected


def test_html_has_every_required_section(project):
    outline = _html_outline(render_html(_report(project)))
    assert [line.split(":")[0] for line in outline] == [
        "summary",
        "scope",
        "inventory",
        "integrity",
        "evaluations",
        "findings",
        "ledger",
        "methodology",
        "disclaimer",
    ]


def test_html_is_self_contained_and_escaped(project):
    html = render_html(_report(project))
    assert "<script" not in html
    assert 'http-equiv="Content-Security-Policy"' in html
    assert "default-src 'none'" in html
    assert not re.search(r'(src|href)="https?://', html)  # no external resources
    assert DISCLAIMER.split(".")[0] in html


# --- content --------------------------------------------------------------------------


def test_evaluation_log_and_max_gap(project):
    evaluations = _report(project)["evaluations"]
    (pair,) = evaluations["targets"]
    assert [r["run_id"] for r in pair["runs"]] == ["run-1", "run-2", "run-3", "run-4"]
    assert pair["evaluations"] == 3
    assert pair["failed"] == 1
    # Successful: 11-01, 11-04, 11-14, then to the end of the period (11-27 12:00).
    assert pair["max_gap_hours"] == pytest.approx(13 * 24 + 12)
    assert pair["weekly"] is False
    assert pair["within_schedule"] is False
    assert evaluations["weekly"] is False
    assert "run-old" not in json.dumps(evaluations)  # outside the period
    html = render_html(_report(project))
    assert "not evaluated" in html  # the failed capture is not shown as clean


def test_weekly_cadence_passes(project):
    with project.open_store() as store:
        report = build_report(
            project,
            store,
            period=Period(datetime(2026, 10, 30, tzinfo=UTC), datetime(2026, 11, 6, tzinfo=UTC)),
            now=NOW,
        )
    (pair,) = report["evaluations"]["targets"]
    assert pair["max_gap_hours"] == pytest.approx(72)
    assert pair["weekly"] is True


def test_findings_show_resolution(project):
    findings = _report(project)["findings"]
    assert findings["items"]
    resolved = [f for f in findings["items"] if f["resolution"]]
    assert resolved
    assert resolved[0]["resolution"]["by"] == "dana"
    assert resolved[0]["resolution"]["note"] == "CHG-42 reviewed"
    assert resolved[0]["state"] == "resolved"
    html = render_html(_report(project))
    assert "resolved by dana" in html
    assert "CHG-42 reviewed" in html


def test_inventory_shows_authorization(project):
    inventory = _report(project)["inventory"]
    (entry,) = inventory["entries"]
    assert entry["approved"] is True
    assert entry["justification"] == "Checkout UI"
    assert entry["ledger_seq"] is not None
    assert "approved by erin" in entry["authorization"]
    assert f"ledger record #{entry['ledger_seq']}" in entry["authorization"]
    assert inventory["summary"]["approved"] == 1
    assert inventory["unlisted"] == []


def test_ledger_section_verified(project):
    ledger = _report(project)["ledger"]
    assert ledger["ok"] is True
    assert ledger["head"]["signature"]
    html = render_html(_report(project))
    assert 'id="ledger-verified"' in html
    assert 'id="ledger-failed"' not in html


def test_tampered_ledger_shows_failed_banner(project):
    with project.open_store() as store, store.db.transaction() as conn:
        conn.execute("UPDATE ledger SET payload = '{\"forged\": true}' WHERE seq = 1")
    report = _report(project)
    assert report["ledger"]["ok"] is False
    assert any("modified" in p for p in report["ledger"]["problems"])
    html = render_html(report)
    assert 'id="ledger-failed"' in html
    assert "LEDGER VERIFICATION FAILED" in html
    assert "record 1 was modified" in html


def test_pinned_key_mismatch_fails_ledger(project):
    other = "A" * 43 + "="
    report = _report(project, public_key=other)
    assert report["ledger"]["ok"] is False
    assert report["ledger"]["key_pinned"] is True


def test_period_must_be_ordered(project):
    from blink_visual.errors import BlinkError

    with project.open_store() as store, pytest.raises(BlinkError, match="start before"):
        build_report(project, store, period=Period(NOW, NOW), now=NOW)


# --- signing ------------------------------------------------------------------------------


def test_sidecar_signature_roundtrip(project, tmp_path):
    report = _report(project)
    (tmp_path / "report.html").write_text("<html></html>", "utf-8")
    from blink_visual.report import sha256_file

    sidecar = sign_report(
        report, project.store_dir, {"report.html": sha256_file(tmp_path / "report.html")}
    )
    public = key_path(project.store_dir).with_suffix(".pub").read_text("ascii").strip()
    assert verify_sidecar(sidecar, directory=tmp_path, public_key=public).ok
    roundtrip = json.loads(json.dumps(sidecar))
    assert verify_sidecar(roundtrip, directory=tmp_path).ok

    forged = json.loads(json.dumps(sidecar))
    forged["findings"]["unresolved"] = 0
    forged["evaluations"]["weekly"] = True
    check = verify_sidecar(forged)
    assert not check.ok
    assert "modified" in check.problems[0]

    (tmp_path / "report.html").write_text("<html>edited</html>", "utf-8")
    edited = verify_sidecar(sidecar, directory=tmp_path)
    assert not edited.ok
    assert "report.html does not match" in edited.problems[0]

    wrong_key = verify_sidecar(sidecar, public_key="B" * 43 + "=")
    assert not wrong_key.ok
    assert verify_sidecar({"schema": "x"}).problems == ("the report has no ed25519 signature",)


def test_sign_needs_the_key(project, tmp_path):
    from blink_visual.errors import BlinkError

    key_path(project.store_dir).unlink()
    with pytest.raises(BlinkError, match="signing key"):
        sign_report({}, project.store_dir, {})


# --- CLI --------------------------------------------------------------------------------------


def test_cli_report_without_pdf(project, tmp_path, capsys):
    out = tmp_path / "evidence"
    code = main(
        ["report", "--out", str(out), "--no-pdf", "--since", "2026-10-28", "--until", "2026-11-27"]
    )
    printed = capsys.readouterr().out
    assert code == 0, printed
    assert (out / "report.html").exists()
    assert (out / "report.json").exists()
    assert not (out / "report.pdf").exists()
    assert "ledger verified" in printed
    sidecar = json.loads((out / "report.json").read_text("utf-8"))
    assert sidecar["period"] == {"from": "2026-10-28T00:00:00Z", "to": "2026-11-27T23:59:59Z"}
    assert set(sidecar["artifacts"]) == {"report.html"}
    pub = key_path(project.store_dir).with_suffix(".pub")
    assert main(["verify-report", str(out), "--public-key", str(pub)]) == 0
    assert "signature valid" in capsys.readouterr().out
    with project.open_store() as store:
        kinds = [r.kind for r in store.ledger.records()]
        assert kinds[-1] == "report.generated"
        assert store.ledger.verify().ok

    (out / "report.html").write_text("tampered", "utf-8")
    assert main(["verify-report", str(out / "report.json"), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False


def test_cli_report_exits_1_on_tampered_ledger(project, tmp_path, capsys):
    with project.open_store() as store, store.db.transaction() as conn:
        conn.execute("DELETE FROM ledger WHERE seq = 2")
    out = tmp_path / "evidence"
    assert main(["report", "--out", str(out), "--no-pdf"]) == 1
    captured = capsys.readouterr()
    assert "LEDGER VERIFICATION FAILED" in captured.err
    assert "LEDGER VERIFICATION FAILED" in (out / "report.html").read_text("utf-8")
    assert json.loads((out / "report.json").read_text("utf-8"))["ledger"]["ok"] is False


def test_cli_report_rejects_bad_dates(project, capsys):
    assert main(["report", "--no-pdf", "--since", "last tuesday"]) == 2
    assert "not an ISO date" in capsys.readouterr().err
    assert main(["report", "--no-pdf", "--days", "0"]) == 2


def test_cli_verify_report_errors(tmp_path, capsys):
    assert main(["verify-report", str(tmp_path / "missing.json")]) == 2
    (tmp_path / "report.json").write_text("not json", "utf-8")
    assert main(["verify-report", str(tmp_path)]) == 2


# --- PDF (browser) ------------------------------------------------------------------------


@pytest.mark.browser
def test_pdf_renders_and_is_not_empty(project, tmp_path, capturer, capsys):
    out = tmp_path / "evidence"
    assert main(["report", "--out", str(out)]) == 0
    pdf = (out / "report.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 10_000
    assert len(re.findall(rb"/Type\s*/Page[^s]", pdf)) >= 2  # a multi-page document
    sidecar = json.loads((out / "report.json").read_text("utf-8"))
    assert set(sidecar["artifacts"]) == {"report.html", "report.pdf"}
    capsys.readouterr()
    assert main(["verify-report", str(out)]) == 0
