"""SQLite index (stdlib ``sqlite3``) with forward-only, numbered migrations."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..errors import StoreError

MIGRATIONS: list[str] = [
    # 1: targets, blobs and snapshots
    """
    CREATE TABLE targets (
        name TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE blobs (
        sha256 TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        media_type TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE snapshots (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL REFERENCES targets(name),
        profile TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL REFERENCES blobs(sha256),
        dom_hash TEXT NOT NULL,
        status INTEGER
    );
    CREATE INDEX snapshots_by_target ON snapshots(target, profile, captured_at);
    CREATE TABLE snapshot_blobs (
        snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
        role TEXT NOT NULL,
        sha256 TEXT NOT NULL REFERENCES blobs(sha256),
        PRIMARY KEY (snapshot_id, role)
    );
    """,
]


class Database:
    def __init__(self, path: Path, migrations: Sequence[str] = MIGRATIONS) -> None:
        self.path = path
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(
                path, timeout=30, check_same_thread=False, isolation_level=None
            )
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open database {path}: {exc}") from None
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate(migrations)

    def _migrate(self, migrations: Sequence[str]) -> None:
        with self._lock:
            current = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if current > len(migrations):
                raise StoreError(
                    f"database {self.path} was created by a newer Blink (schema {current})",
                    hint="upgrade Blink to read this store",
                )
            for number, script in enumerate(migrations[current:], start=current + 1):
                # executescript issues its own COMMIT; run the version bump inside the script.
                self._conn.executescript(
                    f"BEGIN;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;"
                )

    @property
    def schema_version(self) -> int:
        return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
