"""Lab fixture content (no FastAPI import), shared by the lab app and ``blink init --lab``."""

from __future__ import annotations

import base64
import hashlib
from functools import cache
from importlib.resources import files

INLINE_CONFIG = 'window.SHOP_CONFIG = {"currency": "EUR", "locale": "en-GB"};'


@cache
def asset(name: str) -> str:
    return (files("blink_visual.lab") / "assets" / name).read_text(encoding="utf-8")


def sri(content: str, algorithm: str = "sha384") -> str:
    digest = hashlib.new(algorithm, content.encode("utf-8")).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode('ascii')}"
