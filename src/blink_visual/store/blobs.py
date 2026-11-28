"""Content-addressed blob storage under ``.blink/objects/<2 hex>/<62 hex>``."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from pathlib import Path

from ..errors import StoreError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BlobStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, digest: str) -> Path:
        if not _DIGEST.match(digest):
            raise StoreError(f"invalid blob digest {digest!r}")
        return self.root / digest[:2] / digest[2:]

    def put(self, data: bytes) -> str:
        """Store ``data`` once and return its sha256 digest. Existing blobs are never rewritten."""
        digest = sha256_hex(data)
        target = self.path(digest)
        if target.exists():
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.replace(temp, target)
        except OSError:
            temp.unlink(missing_ok=True)
            if not target.exists():
                raise
        return digest

    def get(self, digest: str, *, verify: bool = True) -> bytes:
        try:
            data = self.path(digest).read_bytes()
        except FileNotFoundError:
            raise StoreError(f"blob {digest[:12]}… is missing from the store") from None
        if verify and sha256_hex(data) != digest:
            raise StoreError(f"blob {digest[:12]}… is corrupt (content hash mismatch)")
        return data

    def exists(self, digest: str) -> bool:
        return self.path(digest).exists()
