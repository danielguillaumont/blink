"""Deterministic capture of a payment page into a snapshot bundle.

The browser driver (:mod:`.browser`) needs the ``[capture]`` extra; normalization,
models, HAR scrubbing and TLS inspection are importable without Playwright.
"""

from .models import (
    CookieRecord,
    FormInput,
    FormRecord,
    IframeRecord,
    RequestRecord,
    ScriptRecord,
    Snapshot,
    TlsInfo,
)
from .normalize import normalize_dom

__all__ = [
    "CookieRecord",
    "FormInput",
    "FormRecord",
    "IframeRecord",
    "RequestRecord",
    "ScriptRecord",
    "Snapshot",
    "TlsInfo",
    "normalize_dom",
]
