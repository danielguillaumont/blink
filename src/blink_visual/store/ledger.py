"""Tamper-evident ledger: a hash chain of records whose head is signed with ed25519.

Every scan run, baseline change, approval and alert state change is appended as a record
``{seq, at, kind, payload, prev_hash}`` whose ``hash`` is the SHA-256 of its canonical JSON.
Each record commits to its predecessor, so editing, deleting or reordering a record breaks
the chain. Deleting records from the end is caught by the signed head (``seq`` + ``hash`` of
the last record), which only the holder of the private key can re-sign.

The private key lives in ``.blink/keys/ledger_ed25519`` (mode 0600, never committed). Keep a
copy of the public key fingerprint printed by ``blink init`` somewhere the Blink host cannot
write (for example, in your repository) and pass it to ``blink verify-ledger --public-key``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..errors import StoreError
from .db import Database

GENESIS = "0" * 64
KEY_DIR = "keys"
KEY_FILE = "ledger_ed25519"
HEAD_CONTEXT = b"blink-ledger-head:v1:"


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def record_hash(seq: int, at: str, kind: str, payload: str, prev_hash: str) -> str:
    body = {"seq": seq, "at": at, "kind": kind, "payload": payload, "prev_hash": prev_hash}
    return hashlib.sha256(canonical(body)).hexdigest()


def _head_message(seq: int, digest: str) -> bytes:
    return HEAD_CONTEXT + f"{seq}:{digest}".encode("ascii")


def public_key_text(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def key_fingerprint(public_key: str) -> str:
    """Short, comparable fingerprint of a base64 raw ed25519 public key."""
    return "ed25519:" + hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:32]


def key_path(store_root: Path) -> Path:
    return store_root / KEY_DIR / KEY_FILE


def generate_key(store_root: Path) -> tuple[Path, str]:
    """Create the signing key (0600) and its ``.pub``; never overwrites an existing key."""
    path = key_path(store_root)
    if path.exists():
        return path, public_key_text(load_private_key(path).public_key())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    os.chmod(path, 0o600)
    public = public_key_text(key.public_key())
    path.with_suffix(".pub").write_text(public + "\n", encoding="ascii")
    return path, public


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise StoreError(f"cannot read ledger signing key {path}: {exc}") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise StoreError(f"{path} is not an ed25519 private key")
    return key


def load_public_key(text: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(text.strip(), validate=True))
    except ValueError as exc:
        raise StoreError(f"invalid ed25519 public key: {exc}") from None


@dataclass(frozen=True)
class LedgerRecord:
    seq: int
    at: str
    kind: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str


@dataclass(frozen=True)
class Verification:
    ok: bool
    records: int
    head_seq: int | None
    head_hash: str | None
    public_key: str | None
    problems: tuple[str, ...] = field(default_factory=tuple)

    @property
    def fingerprint(self) -> str | None:
        return key_fingerprint(self.public_key) if self.public_key else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "public_key_fingerprint": self.fingerprint,
            "problems": list(self.problems),
        }


class Ledger:
    def __init__(self, db: Database, store_root: Path) -> None:
        self.db = db
        self.store_root = store_root
        self._key: Ed25519PrivateKey | None = None

    def _signing_key(self, existing_records: int) -> Ed25519PrivateKey:
        if self._key is None:
            path = key_path(self.store_root)
            if not path.exists():
                if existing_records:
                    raise StoreError(
                        f"ledger signing key {path} is missing but the ledger has records",
                        hint="restore the key from backup; Blink will not silently re-key",
                    )
                generate_key(self.store_root)
            self._key = load_private_key(path)
        return self._key

    def append(self, kind: str, payload: Mapping[str, Any], *, at: str) -> LedgerRecord:
        body = canonical(dict(payload)).decode("utf-8")
        with self.db.transaction() as conn:
            last = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            seq = 1 if last is None else int(last["seq"]) + 1
            prev = GENESIS if last is None else str(last["hash"])
            key = self._signing_key(0 if last is None else seq - 1)
            digest = record_hash(seq, at, kind, body, prev)
            conn.execute(
                "INSERT INTO ledger (seq, at, kind, payload, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (seq, at, kind, body, prev, digest),
            )
            signature = base64.b64encode(key.sign(_head_message(seq, digest))).decode("ascii")
            conn.execute(
                "INSERT INTO ledger_head (id, seq, hash, signature, public_key, signed_at) "
                "VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET seq = excluded.seq, "
                "hash = excluded.hash, signature = excluded.signature, "
                "public_key = excluded.public_key, signed_at = excluded.signed_at",
                (seq, digest, signature, public_key_text(key.public_key()), at),
            )
        return LedgerRecord(seq, at, kind, dict(payload), prev, digest)

    def records(self, kinds: set[str] | None = None) -> list[LedgerRecord]:
        rows = self.db.query("SELECT * FROM ledger ORDER BY seq")
        out = []
        for row in rows:
            if kinds is not None and row["kind"] not in kinds:
                continue
            try:
                payload = json.loads(row["payload"])
            except ValueError:
                payload = {"unparseable": True}
            out.append(
                LedgerRecord(
                    row["seq"], row["at"], row["kind"], payload, row["prev_hash"], row["hash"]
                )
            )
        return out

    def verify(self, *, public_key: str | None = None) -> Verification:
        """Recompute the chain and check the signed head.

        ``public_key`` (base64 raw ed25519) pins the expected key; without it the key stored
        next to the private key (``.pub``) is used, and failing that the one in the head.
        """
        problems: list[str] = []
        try:
            rows = self.db.query("SELECT * FROM ledger ORDER BY seq")
            head = self.db.query_one("SELECT * FROM ledger_head WHERE id = 1")
        except sqlite3.Error as exc:
            return Verification(False, 0, None, None, None, (f"cannot read the ledger: {exc}",))
        prev = GENESIS
        for expected, row in enumerate(rows, start=1):
            seq = int(row["seq"])
            if seq != expected:
                problems.append(f"record {expected} is missing (next record is {seq})")
                expected = seq
            if row["prev_hash"] != prev:
                problems.append(f"record {seq} does not follow the previous record")
            digest = record_hash(seq, row["at"], row["kind"], row["payload"], row["prev_hash"])
            if digest != row["hash"]:
                problems.append(f"record {seq} was modified (hash mismatch)")
            prev = row["hash"]
        last_seq = int(rows[-1]["seq"]) if rows else None
        if head is None:
            if rows:
                problems.append("the signed head is missing")
            return Verification(not problems, len(rows), None, None, None, tuple(problems))
        expected_key = public_key or self._stored_public_key() or head["public_key"]
        if head["public_key"] != expected_key:
            problems.append("the head was signed with a different key than expected")
        try:
            load_public_key(expected_key).verify(
                base64.b64decode(head["signature"]), _head_message(head["seq"], head["hash"])
            )
        except (InvalidSignature, ValueError, StoreError):
            problems.append("the head signature is invalid")
        if last_seq is None or head["seq"] != last_seq or head["hash"] != prev:
            problems.append(
                f"the signed head (record {head['seq']}) does not match the last record "
                f"({last_seq}); records were removed or added without signing"
            )
        return Verification(
            not problems,
            len(rows),
            int(head["seq"]),
            str(head["hash"]),
            expected_key,
            tuple(problems),
        )

    def _stored_public_key(self) -> str | None:
        path = key_path(self.store_root).with_suffix(".pub")
        try:
            return path.read_text(encoding="ascii").strip() or None
        except OSError:
            return None
