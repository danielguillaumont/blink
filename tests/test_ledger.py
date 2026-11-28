"""Phase 4 AC: modifying, deleting or reordering any ledger record fails verification."""

from __future__ import annotations

import itertools
import os
import sys

import pytest

from blink_visual.errors import StoreError
from blink_visual.store import Store
from blink_visual.store.ledger import (
    GENESIS,
    generate_key,
    key_fingerprint,
    key_path,
    public_key_text,
)

N = 6


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / ".blink") as opened:
        for i in range(1, N + 1):
            opened.ledger.append("test.event", {"n": i, "note": f"record {i}"}, at=f"2026-11-0{i}Z")
        yield opened


def problems(store: Store) -> list[str]:
    result = store.ledger.verify()
    assert result.ok is (not result.problems)
    return list(result.problems)


def test_intact_ledger_verifies(store):
    result = store.ledger.verify()
    assert result.ok, result.problems
    assert result.records == N
    assert result.head_seq == N
    records = store.ledger.records()
    assert records[0].prev_hash == GENESIS
    assert all(b.prev_hash == a.hash for a, b in itertools.pairwise(records))
    assert result.to_dict()["public_key_fingerprint"].startswith("ed25519:")


def test_empty_ledger_verifies(tmp_path):
    with Store(tmp_path / ".blink") as empty:
        result = empty.ledger.verify()
    assert result.ok
    assert result.records == 0


@pytest.mark.parametrize("seq", range(1, N + 1))
def test_modifying_any_record_fails(store, seq):
    with store.db.transaction() as conn:
        conn.execute(
            "UPDATE ledger SET payload = ? WHERE seq = ?", ('{"n":999,"note":"edited"}', seq)
        )
    assert any(f"record {seq} was modified" in p for p in problems(store))


@pytest.mark.parametrize("column", ["at", "kind"])
def test_modifying_metadata_fails(store, column):
    with store.db.transaction() as conn:
        conn.execute(f"UPDATE ledger SET {column} = 'x' WHERE seq = 3")
    assert any("record 3 was modified" in p for p in problems(store))


def test_rehashing_an_edited_record_still_fails(store):
    """Recomputing the edited record's hash breaks the next record's prev_hash link."""
    from blink_visual.store.ledger import record_hash

    row = store.db.query_one("SELECT * FROM ledger WHERE seq = 3")
    payload = '{"n":3,"note":"forged"}'
    forged = record_hash(3, row["at"], row["kind"], payload, row["prev_hash"])
    with store.db.transaction() as conn:
        conn.execute("UPDATE ledger SET payload = ?, hash = ? WHERE seq = 3", (payload, forged))
    assert any("record 4 does not follow" in p for p in problems(store))


@pytest.mark.parametrize("seq", range(1, N + 1))
def test_deleting_any_record_fails(store, seq):
    with store.db.transaction() as conn:
        conn.execute("DELETE FROM ledger WHERE seq = ?", (seq,))
    found = problems(store)
    assert found, f"deleting record {seq} went unnoticed"
    if seq == N:
        assert any("signed head" in p for p in found)
    else:
        assert any("missing" in p or "does not follow" in p for p in found)


def test_reordering_records_fails(store):
    rows = store.db.query("SELECT * FROM ledger WHERE seq IN (2, 4) ORDER BY seq")
    with store.db.transaction() as conn:
        for row, other in ((rows[0], rows[1]), (rows[1], rows[0])):
            conn.execute(
                "UPDATE ledger SET at = ?, kind = ?, payload = ?, prev_hash = ?, hash = ? "
                "WHERE seq = ?",
                (
                    other["at"],
                    other["kind"],
                    other["payload"],
                    other["prev_hash"],
                    other["hash"],
                    row["seq"],
                ),
            )
    found = problems(store)
    assert any("does not follow" in p or "modified" in p for p in found)


def test_swapping_sequence_numbers_fails(store):
    with store.db.transaction() as conn:
        conn.execute("UPDATE ledger SET seq = 100 WHERE seq = 2")
        conn.execute("UPDATE ledger SET seq = 2 WHERE seq = 5")
        conn.execute("UPDATE ledger SET seq = 5 WHERE seq = 100")
    assert problems(store)


def test_appending_without_the_key_fails(store):
    """A record inserted directly (no head re-sign) is caught by the signed head."""
    from blink_visual.store.ledger import record_hash

    last = store.ledger.records()[-1]
    digest = record_hash(N + 1, "2026-12-01Z", "forged", "{}", last.hash)
    with store.db.transaction() as conn:
        conn.execute(
            "INSERT INTO ledger (seq, at, kind, payload, prev_hash, hash) VALUES (?,?,?,?,?,?)",
            (N + 1, "2026-12-01Z", "forged", "{}", last.hash, digest),
        )
    assert any("signed head" in p for p in problems(store))


def test_tampered_signature_and_foreign_key_fail(store, tmp_path):
    with store.db.transaction() as conn:
        conn.execute("UPDATE ledger_head SET signature = ?", ("AAAA" * 22,))
    assert any("signature is invalid" in p for p in problems(store))

    _, other = generate_key(tmp_path / "other")
    result = store.ledger.verify(public_key=other)
    assert not result.ok
    assert any("different key" in p for p in result.problems)


def test_missing_head_fails(store):
    with store.db.transaction() as conn:
        conn.execute("DELETE FROM ledger_head")
    assert any("head is missing" in p for p in problems(store))


def test_missing_key_with_records_refuses_to_rekey(store):
    path = key_path(store.root)
    path.unlink()
    fresh = type(store.ledger)(store.db, store.root)
    with pytest.raises(StoreError, match="will not silently re-key"):
        fresh.append("x", {}, at="2026-12-01Z")


def test_key_generation(tmp_path):
    path, public = generate_key(tmp_path)
    again, same = generate_key(tmp_path)
    assert again == path
    assert same == public  # never overwritten
    assert path.with_suffix(".pub").read_text("ascii").strip() == public
    assert key_fingerprint(public).startswith("ed25519:")
    from blink_visual.store.ledger import load_private_key

    assert public_key_text(load_private_key(path).public_key()) == public


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not enforced on Windows")
def test_key_file_is_0600(tmp_path):
    path, _ = generate_key(tmp_path)
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_scan_baseline_and_approval_are_ledgered(tmp_path):
    from helpers import snapshot

    with Store(tmp_path / ".blink") as s:
        snap = snapshot()
        s.ensure_target(snap.target, snap.url)
        s.save_snapshot(snap)
        s.set_baseline(snap.target, snap.profile, snap.id, reason="first")
        kinds = [r.kind for r in s.ledger.records()]
        assert kinds == ["baseline.set"]
        assert s.ledger.records()[0].payload["reason"] == "first"
        assert s.ledger.verify().ok
