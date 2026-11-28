"""Inventory model, approval, the inventory detector and CSP suggestions (no browser)."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

import helpers
import pytest
import yaml
from helpers import snapshot

from blink_visual.capture.models import RequestRecord, ScriptRecord
from blink_visual.csp_suggest import suggest_csp
from blink_visual.detect.inventory import InventoryDetector
from blink_visual.detect.scripts import ScriptsDetector
from blink_visual.errors import BlinkError, ConfigError
from blink_visual.findings import Severity
from blink_visual.inventory import (
    DYNAMIC,
    Inventory,
    InventoryEntry,
    approve,
    entry_for,
    load_inventory,
    save_inventory,
    script_type,
    suggested_id,
)
from blink_visual.rules import RuleEngine
from blink_visual.store import Store

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
PAGE = "http://127.0.0.1:9100"
APP = f"{PAGE}/static/app.js"
CDN = "http://127.0.0.1:9101/widget.js"


def script(url: str | None, body: bytes) -> ScriptRecord:
    sha384 = "sha384-" + base64.b64encode(hashlib.sha384(body).digest()).decode()
    return ScriptRecord(url=url, inline=url is None, frame_url=PAGE, sha384=sha384)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / ".blink") as opened:
        yield opened


def context(store, baseline, current, inventory=None):
    return helpers.context(store, baseline, current, inventory=inventory)


def page_snapshot(**kw):
    return snapshot(url=PAGE + "/checkout", final_url=PAGE + "/checkout", **kw)


def approved(entry: InventoryEntry, **kwargs) -> InventoryEntry:
    return approve(
        entry, justification="Checkout UI", owner="web-team", approved_by="alice", now=NOW, **kwargs
    )


def test_entry_for_types_and_ids():
    first = script(APP, b"first")
    third = script(CDN, b"third")
    inline = script(None, b"inline()")
    assert script_type(first, PAGE + "/checkout") == "first-party"
    assert script_type(third, PAGE + "/checkout") == "third-party"
    assert script_type(inline, PAGE) == "inline"
    entry = entry_for(first, PAGE + "/checkout")
    assert entry.id == "127-0-0-1-9100-static-app-js"
    assert entry.expected_hash == first.sha384
    assert not entry.approved
    assert entry_for(inline, PAGE).inline_sha384 == inline.sha384
    assert suggested_id(inline).startswith("inline-")
    long = script(PAGE + "/" + "a" * 200 + ".js", b"x")
    assert len(suggested_id(long)) <= 64


def test_approve_requires_justification_owner_and_approver():
    entry = entry_for(script(APP, b"x"), PAGE)
    done = approved(entry, notes="reviewed")
    assert done.approved
    assert done.approved_at == "2026-11-27T12:00:00Z"
    assert done.notes == "reviewed"
    assert done.pinned
    assert not approved(entry, dynamic=True).pinned
    with pytest.raises(BlinkError, match="justification"):
        approve(entry, justification=" ", owner="o", approved_by="a")
    with pytest.raises(BlinkError, match="owner"):
        approve(entry, justification="j", owner="", approved_by="a")
    with pytest.raises(BlinkError, match="approved-by"):
        approve(entry, justification="j", owner="o", approved_by="")


def test_matching_by_url_pattern_and_inline_hash():
    entry = InventoryEntry(
        id="tag", type="third-party", url_pattern=r"https://cdn\.example/t\.js\?v=\d+"
    )
    assert entry.matches(script("https://cdn.example/t.js?v=12", b"x"))
    assert not entry.matches(script("https://cdn.example/t.js?v=x", b"x"))
    inline = script(None, b"a()")
    assert InventoryEntry(id="i", type="inline", inline_sha384=inline.sha384).matches(inline)
    assert not entry.matches(inline)


def test_validation_errors_are_actionable(tmp_path):
    path = tmp_path / "blink.inventory.yaml"
    path.write_text("version: 1\nscripts:\n  - {id: Bad Id, type: inline}\n", "utf-8")
    with pytest.raises(ConfigError, match=r"scripts.0.id"):
        load_inventory(path)
    path.write_text("scripts:\n  - {id: a, type: inline, expected_hash: md5-x}\n", "utf-8")
    with pytest.raises(ConfigError, match="dynamic"):
        load_inventory(path)
    path.write_text("scripts:\n  - {id: a, type: inline, url_pattern: '('}\n", "utf-8")
    with pytest.raises(ConfigError, match="regular expression"):
        load_inventory(path)
    path.write_text("scripts:\n  - {id: a, type: inline}\n  - {id: a, type: inline}\n", "utf-8")
    with pytest.raises(ConfigError, match="duplicate"):
        load_inventory(path)
    path.write_text("scripts: [", "utf-8")
    with pytest.raises(ConfigError, match="YAML"):
        load_inventory(path)
    assert load_inventory(tmp_path / "missing.yaml") is None


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "blink.inventory.yaml"
    inventory = Inventory(scripts=[approved(entry_for(script(APP, b"x"), PAGE))])
    save_inventory(path, inventory)
    text = path.read_text("utf-8")
    assert text.startswith("# Blink script inventory")
    assert "\r\n" not in text
    assert load_inventory(path) == inventory
    inventory.upsert(inventory.scripts[0].model_copy(update={"notes": "n"}))
    assert len(inventory.scripts) == 1
    assert inventory.get("nope") is None


def _grade(findings):
    return RuleEngine().grade_all(findings)


def test_unapproved_script_is_a_finding_even_in_baseline(store):
    app = script(APP, b"app")
    base = page_snapshot(scripts=[app])
    inventory = Inventory(scripts=[entry_for(app, PAGE)])  # listed, not approved
    ctx = context(store, base, page_snapshot(scripts=[app]), inventory=inventory)
    (finding,) = _grade(InventoryDetector().detect(ctx))
    assert finding.change_type == "unapproved"
    assert finding.attributes["in_baseline"] is True
    assert finding.attributes["listed"] is True
    assert finding.severity == Severity.MEDIUM
    assert "blink approve" in finding.evidence["approve"]

    new = script(CDN, b"new")
    ctx = context(store, base, page_snapshot(scripts=[app, new]), inventory=Inventory())
    graded = {f.subject: f for f in _grade(InventoryDetector().detect(ctx))}
    assert graded[CDN].severity == Severity.HIGH
    assert graded[CDN].attributes["listed"] is False


def test_pinned_hash_change_is_critical_and_dynamic_is_not(store):
    old, new = script(APP, b"v1"), script(APP, b"v2")
    pinned = Inventory(scripts=[approved(entry_for(old, PAGE))])
    ctx = context(
        store, page_snapshot(scripts=[old]), page_snapshot(scripts=[new]), inventory=pinned
    )
    (finding,) = _grade(InventoryDetector().detect(ctx))
    assert finding.change_type == "hash_mismatch"
    assert finding.severity == Severity.CRITICAL
    assert finding.evidence["expected_sha384"] == old.sha384

    dynamic = Inventory(scripts=[approved(entry_for(old, PAGE), dynamic=True)])
    ctx = context(
        store, page_snapshot(scripts=[old]), page_snapshot(scripts=[new]), inventory=dynamic
    )
    assert InventoryDetector().detect(ctx) == []
    (changed,) = _grade(ScriptsDetector().detect(ctx))
    assert changed.change_type == "hash_changed"
    assert changed.attributes["approved_dynamic"] is True
    assert changed.severity == Severity.LOW


def test_no_inventory_file_means_no_inventory_findings(store):
    app = script(APP, b"app")
    assert (
        InventoryDetector().detect(
            context(store, page_snapshot(scripts=[app]), page_snapshot(scripts=[app]))
        )
        == []
    )


def test_skimmer_like_new_script_is_critical(store):
    body = (
        b"var _0x1a2b=1,_0x3c4d=2,_0x5e6f=3,_0x7a8b=4,_0x9c0d=5;"
        b'function z(el){ var n = el.value; navigator.sendBeacon("about:blank", "{}"); return n; }'
        b'var s = document.createElement("script");'
    )
    base = page_snapshot(scripts=())
    digest = store.put_blob(body, "text/javascript")
    bad = replace(script(CDN, body), sha256=digest)
    ctx = context(store, base, page_snapshot(scripts=(bad,)))
    added = next(f for f in _grade(ScriptsDetector().detect(ctx)) if f.change_type == "added")
    assert added.attributes["risk_score"] >= 70
    assert added.severity == Severity.CRITICAL
    assert added.evidence["static_analysis"]["factors"]


def test_suggest_csp_uses_only_approved_entries():
    app, cdn, inline = script(APP, b"a"), script(CDN, b"c"), script(None, b"cfg()")
    rogue = script("http://127.0.0.1:9999/x.js", b"r")
    inventory = Inventory(
        scripts=[
            approved(entry_for(app, PAGE)),
            approved(entry_for(cdn, PAGE)),
            approved(entry_for(inline, PAGE)),
            entry_for(rogue, PAGE),
            approved(InventoryEntry(id="tag", type="third-party", url_pattern=".*")),
        ]
    )
    base = page_snapshot(
        scripts=[app, cdn, inline, rogue],
        requests=[
            RequestRecord(
                url="http://127.0.0.1:9102/collect", method="POST", resource_type="fetch"
            ),
            RequestRecord(url=f"{PAGE}/api", method="GET", resource_type="xhr"),
            RequestRecord(url="http://127.0.0.1:9103/img.png", method="GET", resource_type="image"),
        ],
    )
    suggestion = suggest_csp(inventory, base)
    script_src = suggestion.directives["script-src"]
    assert script_src[:2] == ["'self'", "http://127.0.0.1:9101"]
    assert f"'{inline.sha384}'" in script_src
    assert "http://127.0.0.1:9999" not in script_src
    assert suggestion.directives["connect-src"] == ["'self'", "http://127.0.0.1:9102"]
    assert suggestion.directives["object-src"] == ["'none'"]
    assert any(cdn.sha384 in t and 'crossorigin="anonymous"' in t for t in suggestion.sri_tags)
    assert any("url_pattern" in n for n in suggestion.notes)
    assert any("not approved" in n and "9999" in n for n in suggestion.notes)
    assert suggestion.header.startswith("script-src 'self' http://127.0.0.1:9101")
    assert json.loads(json.dumps(suggestion.to_dict()))["header"] == suggestion.header

    dynamic = Inventory(scripts=[approved(entry_for(cdn, PAGE), dynamic=True)])
    result = suggest_csp(dynamic, base)
    assert result.sri_tags == []
    assert any("dynamic" in n for n in result.notes)
    assert suggest_csp(Inventory(), page_snapshot(scripts=[])).directives["script-src"] == [
        "'none'"
    ]


# --- CLI (stored snapshots only, no browser) ---------------------------------------


@pytest.fixture
def stored_project(write_project, monkeypatch):
    from blink_visual.project import Project

    path = write_project([{"name": "shop", "url": PAGE + "/checkout"}])
    monkeypatch.chdir(path.parent)
    project = Project.load(path)
    app, cdn = script(APP, b"app"), script(CDN, b"cdn")
    with project.open_store() as store:
        store.ensure_target("shop", PAGE + "/checkout")
        snap = page_snapshot(scripts=(app, cdn), target="shop", requests=())
        store.save_snapshot(snap)
        store.set_baseline("shop", "desktop-chrome", snap.id, reason="test")
    return project


def test_cli_inventory_sync_approve_and_check(stored_project, capsys):
    from blink_visual.cli import main

    assert main(["inventory", "--check"]) == 1
    out = capsys.readouterr().out
    assert "UNLISTED" in out
    assert main(["inventory", "--sync"]) == 0
    assert "Added 2 unapproved entries" in capsys.readouterr().out
    data = yaml.safe_load(stored_project.inventory_path.read_text("utf-8"))
    ids = [s["id"] for s in data["scripts"]]
    assert len(ids) == 2
    assert main(["inventory", "--sync"]) == 0
    assert "Added 0" in capsys.readouterr().out

    code = main(
        ["approve", *ids, "--justification", "Checkout", "--owner", "web", "--approved-by", "bob"]
    )
    assert code == 0
    assert capsys.readouterr().out.count("Approved ") == 2
    assert main(["inventory", "--check", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)["scripts"]
    assert all(r["approved"] and r["hash_matches"] for r in rows)

    assert main(["approve", "nope", "--justification", "j", "--owner", "o"]) == 2
    assert "unknown inventory id" in capsys.readouterr().err


def test_cli_approve_discovers_unlisted_scripts(stored_project, capsys):
    from blink_visual.cli import main

    script_id = suggested_id(script(CDN, b"cdn"))
    args = ["approve", script_id, "--justification", "Widget", "--owner", "web", "--dynamic"]
    assert main(args) == 0
    entry = load_inventory(stored_project.inventory_path).get(script_id)
    assert entry is not None
    assert entry.approved
    assert entry.expected_hash == DYNAMIC
    capsys.readouterr()


def test_cli_suggest_csp(stored_project, capsys):
    from blink_visual.cli import main

    assert main(["suggest-csp", "shop"]) == 2
    assert "no inventory" in capsys.readouterr().err
    main(["inventory", "--sync"])
    capsys.readouterr()
    assert main(["suggest-csp", "shop"]) == 0
    out = capsys.readouterr().out
    assert "script-src 'none'" in out  # nothing approved yet
    assert "not approved" in out
    ids = [e.id for e in load_inventory(stored_project.inventory_path).scripts]
    main(["approve", *ids, "--justification", "j", "--owner", "o", "--approved-by", "x"])
    capsys.readouterr()
    assert main(["suggest-csp", "shop", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["directives"]["script-src"] == ["'self'", "http://127.0.0.1:9101"]
    assert len(data["sri"]) == 2
    assert main(["suggest-csp", "shop", "--profile", "mobile-safari-ish"]) == 2
    assert main(["suggest-csp", "missing"]) == 2


def test_cli_inventory_without_snapshots(write_project, monkeypatch, capsys):
    from blink_visual.cli import main

    path = write_project([{"name": "shop", "url": PAGE}])
    monkeypatch.chdir(path.parent)
    assert main(["inventory"]) == 0
    assert "No snapshots found" in capsys.readouterr().out
