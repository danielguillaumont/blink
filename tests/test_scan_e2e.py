"""Phase 2 acceptance: every lab scenario x both profiles, end to end.

Each scenario must produce its expected finding(s) at the expected minimum severity, and
``clean`` / ``noise_only`` must produce no findings at or above ``low``. Every report must
validate against the published findings schema v2.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from blink_visual.cli import main
from blink_visual.findings import Severity
from blink_visual.lab import SCENARIOS, lab_target
from blink_visual.project import Project
from blink_visual.scan import establish_baseline, scan

jsonschema = pytest.importorskip("jsonschema")

pytestmark = [pytest.mark.browser, pytest.mark.integration]

SCHEMA = json.loads(
    (Path(__file__).parents[1] / "docs" / "schemas" / "findings-v2.schema.json").read_text("utf-8")
)
PROFILES = ["desktop-chrome", "mobile-safari-ish"]

H, M, C = Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL
EXPECTED: dict[str, list[tuple[str, str, Severity]]] = {
    "clean": [],
    "noise_only": [],
    "new_third_party_script": [("scripts", "added", H), ("scripts", "sri_missing", M)],
    "modified_approved_script": [("scripts", "hash_changed", H)],
    "inline_script_injected": [("scripts", "inline_added", H), ("dom", "region_changed", H)],
    "csp_removed": [("headers", "csp_removed", H)],
    "csp_weakened_unsafe_inline": [("headers", "csp_weakened", H)],
    "form_action_changed": [("forms", "action_changed", C)],
    "hidden_iframe_added": [("forms", "iframe_added", H), ("network", "new_destination", M)],
    "overlay_form_added": [
        ("forms", "form_added", C),
        ("dom", "region_changed", H),
        ("visual", "region_changed", H),
    ],
    "new_beacon_destination": [("network", "new_destination", H)],
    "visual_payment_area_changed": [("visual", "region_changed", M)],
}


def test_expectations_cover_every_scenario():
    assert set(EXPECTED) == set(SCENARIOS)


@pytest.fixture(scope="module")
def baselined(lab, capturer, tmp_path_factory):
    lab.set_scenario("clean")
    root = tmp_path_factory.mktemp("e2e")
    (root / "blink.yaml").write_text(
        yaml.safe_dump({"targets": [lab_target(lab.checkout_url)]}), encoding="utf-8"
    )
    project = Project.load(root / "blink.yaml")
    target = project.config.targets[0]
    with project.open_store() as store:
        establish_baseline(project, store, target, capturer, reason="e2e clean baseline")
        yield project, store, target
    lab.set_scenario("clean")


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("scenario", list(EXPECTED))
def test_scenario_matrix(baselined, lab, capturer, scenario, profile):
    project, store, target = baselined
    lab.set_scenario(scenario)
    try:
        report = scan(project, store, [target], capturer, profiles=[profile])
    finally:
        lab.set_scenario("clean")
    data = report.to_dict()
    jsonschema.validate(data, SCHEMA)
    (result,) = report.results
    assert result.status == "ok", result.error
    found = {(f.detector, f.change_type): f.severity for f in report.findings}
    detail = "\n".join(
        f"{f.severity.label} {f.detector}.{f.change_type} {f.subject}" for f in report.findings
    )
    for detector, change_type, minimum in EXPECTED[scenario]:
        assert (detector, change_type) in found, f"missing {detector}.{change_type}:\n{detail}"
        assert found[(detector, change_type)] >= minimum, detail
    if not EXPECTED[scenario]:
        assert [f for f in report.findings if f.severity >= Severity.LOW] == [], detail
        assert report.exit_code == 0
    else:
        assert report.exit_code == 1
        assert data["gate"] == "failed"


def test_report_is_persisted(baselined):
    _project, store, target = baselined
    runs = store.db.query("SELECT id FROM runs ORDER BY started_at")
    assert runs, "scans must be recorded"
    report = store.run_report(runs[-1]["id"])
    jsonschema.validate(report, SCHEMA)
    assert store.baseline_id(target.name, "desktop-chrome") is not None


# --- CLI -----------------------------------------------------------------------------


@pytest.fixture
def cli_project(clean_lab, write_project, monkeypatch, capturer):
    path = write_project([lab_target(clean_lab.checkout_url)])
    monkeypatch.chdir(path.parent)
    return path


def test_cli_scan_without_baseline_exits_2(cli_project, capsys):
    assert main(["scan", "--profile", "desktop-chrome"]) == 2
    assert "run `blink baseline lab-checkout`" in capsys.readouterr().out


def test_cli_baseline_then_scan(cli_project, clean_lab, capsys, tmp_path):
    assert main(["baseline", "--profile", "desktop-chrome", "--reason", "initial"]) == 0
    assert "Baseline lab-checkout [desktop-chrome]" in capsys.readouterr().out
    assert main(["scan", "lab-checkout", "--profile", "desktop-chrome"]) == 0
    out = capsys.readouterr().out
    assert "0 finding(s)" in out
    assert "Gate: passed" in out

    clean_lab.set_scenario("csp_removed")
    output = tmp_path / "evidence" / "scan.json"
    code = main(["scan", "--all", "--profile", "desktop-chrome", "--json", "--output", str(output)])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    jsonschema.validate(report, SCHEMA)
    assert report["findings"][0]["change_type"] == "csp_removed"
    assert json.loads(output.read_text("utf-8")) == report
    # Never overwrite evidence.
    assert main(["scan", "--profile", "desktop-chrome", "--output", str(output)]) == 2

    assert main(["scan", "--profile", "desktop-chrome", "--fail-on", "critical"]) == 0
    assert "Gate: passed (0 finding(s) at or above critical)" in capsys.readouterr().out
    assert main(["scan", "--profile", "desktop-chrome", "--fail-on", "none"]) == 0
    assert "Gate: skipped" in capsys.readouterr().out


def test_cli_scan_capture_failure_exits_3(write_project, monkeypatch, capsys, capturer):
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    path = write_project([{"name": "down", "url": f"http://127.0.0.1:{port}/", "timeout_s": 5}])
    monkeypatch.chdir(path.parent)
    assert main(["scan"]) == 3
    assert "CAPTURE_FAILED" in capsys.readouterr().out


def test_cli_scan_usage_errors(write_project, monkeypatch, capsys):
    path = write_project([])
    monkeypatch.chdir(path.parent)
    assert main(["scan"]) == 2
    assert "no targets configured" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["scan", "--fail-on", "urgent"])
