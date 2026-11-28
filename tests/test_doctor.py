"""``blink doctor``: one test per check, plus the command's exit codes and JSON output."""

from __future__ import annotations

import json
import os

import pytest
from helpers import snapshot

from blink_visual import doctor
from blink_visual.cli import main
from blink_visual.doctor import FAIL, OK, WARN
from blink_visual.project import Project
from blink_visual.store.ledger import key_path


@pytest.fixture
def project(tmp_path):
    config = tmp_path / "blink.yaml"
    assert main(["init", "--url", "https://shop.example/checkout", "--config", str(config)]) == 0
    return Project.load(config)


def test_python_version():
    assert doctor.check_python((3, 12, 1)).status == OK
    old = doctor.check_python((3, 10, 9))
    assert old.status == FAIL
    assert "3.11" in (old.fix or "")


def test_extras_missing_and_present():
    checks = doctor.check_extras(has=lambda module: module != "fastapi")
    by_name = {c.name: c for c in checks}
    assert by_name["extra:capture"].status == OK
    server = by_name["extra:server"]
    assert server.status == WARN
    assert "fastapi" in server.detail
    assert server.fix == 'python -m pip install "blink-checkout[server]"'


def test_chromium_present_missing_and_broken(tmp_path):
    exe = tmp_path / "chrome"
    exe.write_bytes(b"")
    assert doctor.check_chromium(lambda: str(exe)).status == OK
    missing = doctor.check_chromium(lambda: str(tmp_path / "nope"))
    assert missing.status == FAIL
    assert "playwright install chromium" in (missing.fix or "")

    def broken() -> str:
        raise RuntimeError("driver exited")

    assert "driver exited" in doctor.check_chromium(broken).detail


def test_chromium_without_playwright(monkeypatch):
    monkeypatch.setattr(doctor, "_has", lambda module: False)
    assert doctor.check_chromium().status == WARN


def test_config_missing_invalid_empty_and_ok(tmp_path, project):
    check, loaded = doctor.check_config(tmp_path / "absent.yaml")
    assert (check.status, loaded) == (WARN, None)
    assert "blink init" in (check.fix or "")

    bad = tmp_path / "bad.yaml"
    bad.write_text("targets: [{name: 'x'}]\n", encoding="utf-8")
    check, loaded = doctor.check_config(bad)
    assert (check.status, loaded) == (FAIL, None)

    empty = tmp_path / "empty.yaml"
    empty.write_text("version: 1\n", encoding="utf-8")
    assert doctor.check_config(empty)[0].status == WARN

    check, loaded = doctor.check_config(project.config_path)
    assert check.status == OK
    assert "1 target" in check.detail
    assert loaded is not None


def test_store_ok_missing_and_corrupt(tmp_path, project):
    assert doctor.check_store(project).status == OK
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    (fresh / "blink.yaml").write_text("version: 1\n", encoding="utf-8")
    assert doctor.check_store(Project.load(fresh / "blink.yaml")).status == WARN

    (project.store_dir / "blink.db").write_bytes(b"this is not a sqlite database" * 100)
    corrupt = doctor.check_store(project)
    assert corrupt.status == FAIL
    assert "backup" in (corrupt.fix or "")


def test_keys_token_and_ledger(project, monkeypatch):
    by_name = {c.name: c for c in doctor.check_keys(project)}
    assert by_name["ledger-key"].status == OK
    assert by_name["ledger"].status == OK
    assert by_name["api-token"].status == OK

    with project.open_store() as store:
        store.ledger.append("test", {"n": 1}, at="2026-11-28T00:00:00Z")
        with store.db.transaction() as conn:
            conn.execute("UPDATE ledger SET payload = '{\"n\":2}' WHERE kind = 'test'")
    (project.store_dir / "blink.token").unlink()
    monkeypatch.delenv("BLINK_TOKEN", raising=False)
    key_path(project.store_dir).unlink()
    by_name = {c.name: c for c in doctor.check_keys(project)}
    assert by_name["ledger-key"].status == WARN
    assert by_name["ledger"].status == FAIL
    assert by_name["api-token"].status == WARN


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_key_readable_by_others_fails(project):
    key_path(project.store_dir).chmod(0o644)
    key = next(c for c in doctor.check_keys(project) if c.name == "ledger-key")
    assert key.status == FAIL
    assert "chmod 600" in (key.fix or "")


def test_baselines_missing_then_present(project):
    check = doctor.check_baselines(project)
    assert check.status == WARN
    assert "--if-missing" in (check.fix or "")
    target = project.config.targets[0]
    with project.open_store() as store:
        for profile in target.profiles:
            snap = snapshot(target=target.name, profile=profile, id=f"snap-{profile}")
            store.save_snapshot(snap)
            store.set_baseline(target.name, profile, snap.id)
    assert doctor.check_baselines(project).status == OK


def test_command_exit_codes_and_json(project, capsys, tmp_path):
    assert main(["doctor", "--no-browser", "--config", str(project.config_path)]) == 0
    out = capsys.readouterr().out
    assert "fix: blink baseline --if-missing" in out

    assert main(["doctor", "--no-browser", "--json", "--config", str(project.config_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert {c["name"] for c in payload["checks"]} >= {"python", "config", "store", "ledger"}

    bad = tmp_path / "bad.yaml"
    bad.write_text("targets: 3\n", encoding="utf-8")
    assert main(["doctor", "--no-browser", "--config", str(bad)]) == 1
    assert "Some checks failed" in capsys.readouterr().out
