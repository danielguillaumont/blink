"""Local evidence store: content-addressed blobs plus a SQLite index."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..capture.models import Snapshot
from ..errors import StoreError
from ..serde import dumps, from_dict
from .blobs import BlobStore, sha256_hex
from .db import Database

__all__ = ["BlobStore", "Database", "Store", "sha256_hex", "utc_now"]

DB_FILENAME = "blink.db"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Store:
    """The ``.blink/`` directory of one Blink project."""

    def __init__(self, root: Path) -> None:
        self.root = root
        try:
            (root / "objects").mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreError(
                f"cannot create store directory {root}: {exc.strerror or exc}"
            ) from None
        self.blobs = BlobStore(root / "objects")
        self.db = Database(root / DB_FILENAME)

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- blobs ---------------------------------------------------------------------
    def put_blob(self, data: bytes, media_type: str) -> str:
        digest = self.blobs.put(data)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO blobs (sha256, size, media_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (digest, len(data), media_type, utc_now()),
            )
        return digest

    def get_blob(self, digest: str) -> bytes:
        return self.blobs.get(digest)

    # -- targets and snapshots --------------------------------------------------
    def ensure_target(self, name: str, url: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO targets (name, url, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET url = excluded.url",
                (name, url, utc_now()),
            )

    def save_snapshot(self, snapshot: Snapshot) -> str:
        """Persist the manifest and index it. Referenced blobs must already be stored."""
        for role, digest in snapshot.blobs.items():
            if not self.blobs.exists(digest):
                raise StoreError(f"snapshot {snapshot.id}: blob for {role} was not stored")
        manifest = dumps(snapshot).encode("utf-8")
        manifest_digest = self.put_blob(manifest, "application/vnd.blink.snapshot+json")
        self.ensure_target(snapshot.target, snapshot.url)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO snapshots (id, target, profile, captured_at, manifest_sha256, "
                "dom_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    snapshot.id,
                    snapshot.target,
                    snapshot.profile,
                    snapshot.captured_at,
                    manifest_digest,
                    snapshot.dom_hash,
                    snapshot.status,
                ),
            )
            conn.executemany(
                "INSERT INTO snapshot_blobs (snapshot_id, role, sha256) VALUES (?, ?, ?)",
                [(snapshot.id, role, digest) for role, digest in sorted(snapshot.blobs.items())],
            )
        return manifest_digest

    def load_snapshot(self, snapshot_id: str) -> Snapshot:
        row = self.db.query_one(
            "SELECT manifest_sha256 FROM snapshots WHERE id = ?", (snapshot_id,)
        )
        if row is None:
            raise StoreError(f"unknown snapshot '{snapshot_id}'")
        data = json.loads(self.get_blob(row["manifest_sha256"]).decode("utf-8"))
        try:
            return from_dict(Snapshot, data)
        except (ValueError, TypeError) as exc:
            raise StoreError(f"snapshot {snapshot_id} manifest is invalid: {exc}") from None

    def snapshot_ids(self, target: str | None = None, profile: str | None = None) -> list[str]:
        sql = "SELECT id FROM snapshots WHERE 1=1"
        params: list[str] = []
        if target is not None:
            sql += " AND target = ?"
            params.append(target)
        if profile is not None:
            sql += " AND profile = ?"
            params.append(profile)
        sql += " ORDER BY captured_at, id"
        return [row["id"] for row in self.db.query(sql, params)]
