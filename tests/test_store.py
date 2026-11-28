import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from blink_visual.capture.har import REDACTED, scrub_har, scrub_har_bytes
from blink_visual.capture.models import (
    Box,
    CookieRecord,
    FormInput,
    FormRecord,
    Initiator,
    RegionCapture,
    ScriptRecord,
    Snapshot,
    origin_of,
)
from blink_visual.errors import StoreError
from blink_visual.serde import dumps, from_dict
from blink_visual.store import Store
from blink_visual.store.blobs import BlobStore, sha256_hex
from blink_visual.store.db import Database


def make_snapshot(store: Store, **overrides) -> Snapshot:
    dom = store.put_blob(b"<html></html>", "text/html")
    snap = Snapshot(
        id="20260101T000000000000Z-abcdef",
        target="checkout",
        profile="desktop-chrome",
        url="https://shop.example/checkout",
        final_url="https://shop.example/checkout",
        captured_at="2026-01-01T00:00:00.000Z",
        duration_ms=10,
        status=200,
        user_agent="UA",
        viewport=(1280, 900),
        dom_hash=sha256_hex(b"<html></html>"),
        headers={"content-security-policy": "script-src 'self'"},
        scripts=(
            ScriptRecord(
                url="https://cdn.example/a.js",
                inline=False,
                frame_url="https://shop.example/checkout",
                sha384="sha384-abc",
                initiator=Initiator("parser", "https://shop.example/checkout", ("f@x:1",)),
            ),
        ),
        requests=(),
        forms=(
            FormRecord(
                action="https://shop.example/pay",
                method="post",
                frame_url="https://shop.example/checkout",
                inputs=(FormInput("cardnumber", "text", "cc-number"),),
                box=Box(1, 2, 3, 4),
            ),
        ),
        iframes=(),
        cookies=(CookieRecord("sid", "shop.example", "/", True, True, "Lax", True),),
        blobs={"dom": dom},
        payment_region=RegionCapture("#payment", True, Box(0, 0, 10, 10)),
    )
    return replace(snap, **overrides)


def test_blob_store_is_content_addressed(tmp_path: Path):
    blobs = BlobStore(tmp_path)
    digest = blobs.put(b"hello")
    assert digest == sha256_hex(b"hello")
    assert blobs.put(b"hello") == digest
    assert blobs.get(digest) == b"hello"
    blobs.path(digest).write_bytes(b"tampered")
    with pytest.raises(StoreError, match="corrupt"):
        blobs.get(digest)
    with pytest.raises(StoreError, match="missing"):
        blobs.get("0" * 64)
    with pytest.raises(StoreError, match="invalid blob digest"):
        blobs.path("../etc/passwd")


def test_snapshot_round_trip(tmp_path: Path):
    with Store(tmp_path / ".blink") as store:
        snap = make_snapshot(store)
        store.save_snapshot(snap)
        loaded = store.load_snapshot(snap.id)
        assert loaded == snap
        assert loaded.scripts[0].key == "https://cdn.example/a.js"
        assert store.snapshot_ids("checkout") == [snap.id]
        assert store.snapshot_ids("other") == []
        with pytest.raises(StoreError, match="unknown snapshot"):
            store.load_snapshot("nope")


def test_snapshot_requires_stored_blobs(tmp_path: Path):
    with Store(tmp_path / ".blink") as store:
        snap = make_snapshot(store, blobs={"dom": "f" * 64})
        with pytest.raises(StoreError, match="was not stored"):
            store.save_snapshot(snap)


def test_newer_schema_is_refused(tmp_path: Path):
    path = tmp_path / "x.db"
    Database(path).close()
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 999")
    conn.close()
    with pytest.raises(StoreError, match="newer Blink"):
        Database(path)


def test_serde_rejects_unknown_fields():
    with pytest.raises(ValueError, match="unknown field"):
        from_dict(Box, {"x": 1, "y": 1, "width": 1, "height": 1, "z": 1})
    with pytest.raises(ValueError, match="missing field"):
        from_dict(Box, {"x": 1})
    with pytest.raises(ValueError, match="expected str"):
        from_dict(FormInput, {"name": 1, "type": "text"})
    box = from_dict(Box, json.loads(dumps(Box(1, 2, 3, 4))))
    assert box == Box(1.0, 2.0, 3.0, 4.0)


def test_inline_script_key_and_origin():
    inline = ScriptRecord(url=None, inline=True, frame_url="x", sha384="sha384-q")
    assert inline.key == "inline:sha384-q"
    assert origin_of("https://a.example:443/x") == "https://a.example"
    assert origin_of("http://127.0.0.1:8780/x") == "http://127.0.0.1:8780"
    assert origin_of("data:text/plain,hi") is None
    assert Box(0, 0, 10, 10).intersects(Box(5, 5, 10, 10))
    assert not Box(0, 0, 10, 10).intersects(Box(10, 0, 5, 5))


def test_har_scrubbing_removes_secrets():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "headers": [
                            {"name": "Authorization", "value": "Bearer secret-token"},
                            {"name": "Cookie", "value": "sid=secret"},
                            {"name": "Accept", "value": "*/*"},
                        ],
                        "cookies": [{"name": "sid", "value": "secret"}],
                        "postData": {"mimeType": "application/json", "text": '{"ping":1}'},
                    },
                    "response": {
                        "headers": [{"name": "Set-Cookie", "value": "sid=secret2"}],
                        "cookies": [{"name": "sid", "value": "secret2", "httpOnly": True}],
                        "content": {"size": 3, "text": "abc"},
                    },
                }
            ]
        }
    }
    scrubbed = json.dumps(scrub_har(har))
    assert "secret" not in scrubbed
    assert '{"ping":1}' not in scrubbed
    assert REDACTED in scrubbed
    assert "*/*" in scrubbed
    assert b"secret" not in scrub_har_bytes(json.dumps(har).encode())
