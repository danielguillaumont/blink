"""Generate a minimal CSP and SRI attributes from the approved inventory."""

from __future__ import annotations

import html
from dataclasses import dataclass, field

from .capture.models import ScriptRecord, Snapshot, origin_of
from .inventory import Inventory

CONNECT_TYPES = frozenset({"fetch", "xhr", "ping", "beacon", "websocket", "eventsource"})
HARDENING = {
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "frame-ancestors": ["'none'"],
}


@dataclass(frozen=True)
class CspSuggestion:
    directives: dict[str, list[str]]
    sri_tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def header(self) -> str:
        return "; ".join(f"{name} {' '.join(values)}" for name, values in self.directives.items())

    def to_dict(self) -> dict[str, object]:
        return {
            "header": self.header,
            "directives": self.directives,
            "sri": self.sri_tags,
            "notes": self.notes,
        }


def suggest_csp(inventory: Inventory, baseline: Snapshot) -> CspSuggestion:
    """``script-src`` from approved scripts, ``connect-src`` from the baseline's requests.

    Only *approved* inventory entries contribute; scripts seen in the baseline that are not
    approved are listed in the notes so they are not silently allowed.
    """
    page = origin_of(baseline.final_url or baseline.url)
    script_src: list[str] = []
    notes: list[str] = []
    sri_tags: list[str] = []

    def allow(source: str) -> None:
        if source not in script_src:
            script_src.append(source)

    for entry in inventory.scripts:
        if not entry.approved:
            continue
        if entry.type == "inline":
            if entry.inline_sha384:
                allow(f"'{entry.inline_sha384}'")
            continue
        if entry.url is None:
            notes.append(
                f"{entry.id}: matched by url_pattern only; add its origin to script-src manually"
            )
            continue
        origin = origin_of(entry.url)
        if origin is None:
            continue
        allow("'self'" if origin == page else origin)
        if entry.pinned:
            sri = entry.sri or entry.expected_hash
            crossorigin = ' crossorigin="anonymous"' if origin != page else ""
            sri_tags.append(
                f'<script src="{html.escape(entry.url)}" integrity="{html.escape(sri)}"'
                f"{crossorigin}></script>"
            )
        else:
            notes.append(f"{entry.id}: approved as dynamic, so no SRI hash can be pinned")
    unapproved = sorted(
        s.key for s in baseline.scripts if s.is_javascript and not _approved(inventory, s)
    )
    for key in unapproved:
        notes.append(f"not approved, excluded from script-src: {key[:120]}")
    connect = ["'self'"]
    for request in baseline.requests:
        origin = request.origin
        if (
            request.resource_type in CONNECT_TYPES
            and origin
            and origin != page
            and origin not in connect
        ):
            connect.append(origin)
    directives = {"script-src": _ordered(script_src) or ["'none'"], "connect-src": connect}
    directives.update({k: list(v) for k, v in HARDENING.items()})
    return CspSuggestion(directives=directives, sri_tags=sri_tags, notes=notes)


def _approved(inventory: Inventory, script: ScriptRecord) -> bool:
    entry = inventory.match(script)
    return bool(entry and entry.approved)


def _ordered(sources: list[str]) -> list[str]:
    """Deterministic order: keywords such as 'self' first, then origins, then hashes."""

    def rank(source: str) -> tuple[int, str]:
        if source.startswith("'sha"):
            return (2, source)
        return (0, source) if source.startswith("'") else (1, source)

    return sorted(set(sources), key=rank)
