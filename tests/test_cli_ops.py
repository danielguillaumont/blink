"""CLI: blink init key, verify-ledger, alerts and daemon --once (lab, loopback only)."""

from __future__ import annotations

import json

import pytest
import yaml

from blink_visual.cli import main
from blink_visual.lab import lab_target
from blink_visual.project import Project


def test_init_generates_the_ledger_key(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    out = capsys.readouterr().out
    assert "Ledger public key: ed25519:" in out
    assert (tmp_path / ".blink" / "keys" / "ledger_ed25519").exists()
    assert (tmp_path / ".blink" / "keys" / "ledger_ed25519.pub").exists()
    assert ".blink/" in (tmp_path / ".gitignore").read_text("utf-8")


def test_verify_ledger_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["init"])
    capsys.readouterr()
    project = Project.load(tmp_path / "blink.yaml")
    with project.open_store() as store:
        for i in range(3):
            store.ledger.append("test", {"i": i}, at=f"2026-11-2{i}T00:00:00Z")
    assert main(["verify-ledger"]) == 0
    assert "Ledger OK: 3 record(s)" in capsys.readouterr().out
    pub = tmp_path / ".blink" / "keys" / "ledger_ed25519.pub"
    assert main(["verify-ledger", "--public-key", str(pub), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    with project.open_store() as store, store.db.transaction() as conn:
        conn.execute("UPDATE ledger SET payload = '{\"i\":42}' WHERE seq = 2")
    assert main(["verify-ledger"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "record 2 was modified" in out
    assert main(["verify-ledger", "--public-key", str(tmp_path / "missing.pub")]) == 2


def test_alerts_cli_lifecycle(tmp_path, monkeypatch, capsys):
    from blink_visual.alerts import AlertManager
    from blink_visual.findings import Finding, Severity

    monkeypatch.chdir(tmp_path)
    main(["init"])
    capsys.readouterr()
    assert main(["alerts"]) == 0
    assert "No alerts." in capsys.readouterr().out
    project = Project.load(tmp_path / "blink.yaml")
    finding = Finding(
        "schedule",
        "missed_evaluation",
        "shop/desktop-chrome",
        "No evaluation",
        "shop",
        "desktop-chrome",
        severity=Severity.HIGH,
        why="w",
    )
    with project.open_store() as store:
        AlertManager(store).ingest("run-1", [finding])
    assert main(["alerts", "list", "--json"]) == 0
    (alert,) = json.loads(capsys.readouterr().out)
    assert alert["state"] == "open"
    assert main(["alerts", "ack", finding.id, "--by", "alice", "--note", "looking"]) == 0
    assert "acknowledged (by alice)" in capsys.readouterr().out
    assert main(["alerts", "ack", finding.id, "--by", "alice"]) == 2
    assert "cannot become acknowledged" in capsys.readouterr().err
    assert main(["alerts", "accept", finding.id, "--by", "bob", "--note", "planned outage"]) == 0
    capsys.readouterr()
    assert main(["alerts", "list", "--state", "accepted-change"]) == 0
    assert finding.id in capsys.readouterr().out
    assert main(["alerts", "show", finding.id]) == 0
    out = capsys.readouterr().out
    assert "acknowledged -> accepted-change  by bob  planned outage" in out
    assert main(["alerts", "show", finding.id, "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["events"]) == 3
    assert main(["alerts", "reopen", finding.id, "--by", "carol"]) == 0
    assert main(["alerts", "list", "--all"]) == 0
    assert main(["verify-ledger"]) == 0


@pytest.mark.browser
@pytest.mark.integration
def test_daemon_once_against_the_lab(clean_lab, tmp_path, monkeypatch, capturer, capsys):
    pytest.importorskip("apscheduler")
    target = lab_target(clean_lab.checkout_url)
    target["profiles"] = ["desktop-chrome"]
    config = {
        "schedule": {"interval": "1d", "retries": 0},
        "alerts": {
            "min_severity": "high",
            "sinks": [{"name": "file", "type": "jsonl", "path": "alerts.jsonl"}],
        },
        "targets": [target],
    }
    (tmp_path / "blink.yaml").write_text(yaml.safe_dump(config), "utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["baseline"]) == 0
    assert main(["daemon", "--once"]) == 0
    assert not (tmp_path / "alerts.jsonl").exists()  # clean: nothing to alert

    clean_lab.set_scenario("form_action_changed")
    assert main(["daemon", "--once"]) == 0
    alerts = [json.loads(x) for x in (tmp_path / "alerts.jsonl").read_text("utf-8").splitlines()]
    assert any(a["change_type"] == "action_changed" and a["severity"] == "critical" for a in alerts)
    count = len(alerts)
    assert main(["daemon", "--once"]) == 0  # same findings again: deduplicated, no new alerts
    assert len((tmp_path / "alerts.jsonl").read_text("utf-8").splitlines()) == count
    logs = capsys.readouterr().err.strip().splitlines()
    events = {json.loads(line)["event"] for line in logs if line.startswith("{")}
    assert {"scan.started", "scan.finished"} <= events
    assert main(["verify-ledger"]) == 0


def test_daemon_usage_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    main(["init"])
    capsys.readouterr()
    assert main(["daemon", "--once"]) == 2
    assert "no targets" in capsys.readouterr().err
