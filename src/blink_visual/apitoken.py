"""The dashboard/API bearer token: ``.blink/blink.token`` (0600) or ``$BLINK_TOKEN``."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .errors import ConfigError

# A file name and an environment variable name, not secrets.
TOKEN_FILE = "blink.token"  # noqa: S105  # nosec B105
TOKEN_ENV = "BLINK_TOKEN"  # noqa: S105  # nosec B105


def token_path(store_dir: Path) -> Path:
    return store_dir / TOKEN_FILE


def ensure_token(store_dir: Path) -> tuple[Path, bool]:
    """Create the API token file (0600) if it does not exist. Returns (path, created)."""
    path = token_path(store_dir)
    if path.exists():
        return path, False
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(secrets.token_urlsafe(32) + "\n")
    os.chmod(path, 0o600)
    return path, True


def load_token(store_dir: Path) -> str:
    env = os.environ.get(TOKEN_ENV, "").strip()
    if env:
        return env
    path, _ = ensure_token(store_dir)
    token = path.read_text(encoding="ascii").strip()
    if len(token) < 16:
        raise ConfigError(f"{path} holds a token shorter than 16 characters")
    return token
