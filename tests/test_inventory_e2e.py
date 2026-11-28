"""Phase 3 acceptance against the localhost lab: inventory, approvals and suggest-csp."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blink_visual.cli import main
from blink_visual.findings import Severity
from blink_visual.lab import lab_target
from blink_visual.store import Store

jsonschema = pytest.importorskip("jsonschema")
SCHEMA = json.loads(
    (Path(__file__).parents[1] / "docs" / "schemas" / "findings-v2.schema.json").read_text("utf-8")
)
pytestmark = [pytest.mark.browser, pytest.mark.integration]


@pytest.fixture
def approved_project(clean_lab, write_project, monkeypatch, capturer, capsys):
    path = write_project([lab_target(clean_lab.checkout_url)])
    monkeypatch.chdir(path.parent)
    assert main(["baseline", "--profile", "desktop-chrome"]) == 0
    assert main(["inventory", "--sync", "--profile", "desktop-chrome"]) == 0
    assert main(["inventory", "--json"]) == 0
    capsys.readouterr()
    main(["inventory", "--json"])
    ids = [row["id"] for row in json.loads(capsys.readouterr().out)["scripts"]]
    assert len(ids) >= 3  # app.js, widget.js, analytics.js and the inline config
    args = ["approve", *ids, "--justification", "Lab checkout", "--owner", "qa"]
    assert main([*args, "--approved-by", "tester"]) == 0
    capsys.readouterr()
    return path


def _scan(capsys) -> tuple[int, dict]:
    code = main(["scan", "--profile", "desktop-chrome", "--json", "--fail-on", "high"])
    report = json.loads(capsys.readouterr().out)
    jsonschema.validate(report, SCHEMA)
    return code, report


def _found(report: dict) -> dict[tuple[str, str], Severity]:
    return {
        (f["detector"], f["change_type"]): Severity.parse(f["severity"]) for f in report["findings"]
    }


def test_clean_scan_with_approved_inventory_has_no_findings(approved_project, capsys):
    code, report = _scan(capsys)
    assert code == 0, report["findings"]
    assert [f for f in report["findings"] if Severity.parse(f["severity"]) >= Severity.LOW] == []


def test_modified_approved_script_is_critical(approved_project, clean_lab, capsys):
    clean_lab.set_scenario("modified_approved_script")
    code, report = _scan(capsys)
    assert code == 1
    found = _found(report)
    assert found[("inventory", "hash_mismatch")] == Severity.CRITICAL
    assert report["summary"]["max_severity"] == "critical"
    mismatch = next(f for f in report["findings"] if f["change_type"] == "hash_mismatch")
    assert mismatch["evidence"]["approved_by"] == "tester"


def test_new_unapproved_script_is_high(approved_project, clean_lab, capsys):
    clean_lab.set_scenario("new_third_party_script")
    code, report = _scan(capsys)
    assert code == 1
    found = _found(report)
    assert found[("inventory", "unapproved")] >= Severity.HIGH
    added = next(f for f in report["findings"] if f["change_type"] == "added")
    assert added["attributes"]["risk_score"] < 30
    assert added["attributes"]["approved"] is False


def test_suggest_csp_for_lab(approved_project, clean_lab, capsys):
    assert main(["suggest-csp", "lab-checkout", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    script_src = data["directives"]["script-src"]
    assert script_src[0] == "'self'"
    assert any(s.startswith("'sha384-") for s in script_src)  # the inline config script
    assert len(data["sri"]) >= 2


def test_blocked_blob_write_keeps_hash_only(clean_lab, write_project, monkeypatch, capturer):
    """Some hosts' antivirus refuses to write skimmer-like files; capture must still finish."""
    from blink_visual.capture.service import capture_target
    from blink_visual.project import Project

    path = write_project([lab_target(clean_lab.checkout_url)])
    project = Project.load(path)
    original = Store.put_blob

    def put_blob(self, data, media_type):
        if media_type == "text/javascript":
            raise PermissionError(5, "Access is denied")
        return original(self, data, media_type)

    monkeypatch.setattr(Store, "put_blob", put_blob)
    with project.open_store() as store:
        (snap,) = capture_target(
            project,
            project.config.targets[0],
            store,
            profiles=["desktop-chrome"],
            capturer=capturer,
        )
    assert snap.scripts
    assert all(s.sha256 is None and s.sha384 for s in snap.scripts)
    assert any("could not store the body" in w for w in snap.warnings)
