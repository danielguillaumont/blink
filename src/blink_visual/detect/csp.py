"""Content-Security-Policy parsing, weakness checks and directive-level diffs."""

from __future__ import annotations

import re
from dataclasses import dataclass

Directives = dict[str, tuple[str, ...]]

KEYWORDS = frozenset(
    {
        "'self'",
        "'none'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
        "'strict-dynamic'",
        "'report-sample'",
        "'wasm-unsafe-eval'",
        "'inline-speculation-rules'",
    }
)
WILDCARD_SOURCES = frozenset({"*", "http:", "https:", "data:", "blob:", "filesystem:"})
WEAKNESS_TOKENS = {
    "unsafe-inline": "'unsafe-inline'",
    "unsafe-eval": "'unsafe-eval'",
}
_NONCE = re.compile(r"^'nonce-[^']*'$", re.IGNORECASE)


def _source(token: str) -> str:
    lowered = token.lower()
    if lowered in KEYWORDS:
        return lowered
    if _NONCE.match(token):
        return "'nonce-*'"  # nonces rotate per response by design
    if lowered.startswith(("'sha256-", "'sha384-", "'sha512-")):
        algorithm, _, digest = token.partition("-")
        return f"{algorithm.lower()}-{digest}"
    return lowered


def parse_csp(header: str) -> Directives:
    """Parse a CSP header value. With several policies, the first definition of a directive
    wins (a conservative simplification documented in docs/detectors.md)."""
    directives: Directives = {}
    for policy in re.split(r"[\n,]", header):
        for part in policy.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            if name not in directives:
                directives[name] = tuple(_source(t) for t in tokens[1:])
    return directives


def script_policy(directives: Directives) -> tuple[str, ...] | None:
    for name in ("script-src", "default-src"):
        if name in directives:
            return directives[name]
    return None


def weaknesses(directives: Directives) -> set[str]:
    sources = script_policy(directives)
    if sources is None:
        return {"no-script-policy"}
    found = {name for name, token in WEAKNESS_TOKENS.items() if token in sources}
    if any(s in WILDCARD_SOURCES for s in sources):
        found.add("wildcard-source")
    return found


@dataclass(frozen=True)
class CspDiff:
    directives_added: tuple[str, ...]
    directives_removed: tuple[str, ...]
    sources_added: dict[str, tuple[str, ...]]
    sources_removed: dict[str, tuple[str, ...]]

    @property
    def empty(self) -> bool:
        return not (
            self.directives_added
            or self.directives_removed
            or self.sources_added
            or self.sources_removed
        )


def diff_csp(
    before: Directives, after: Directives, *, ignore: frozenset[str] = frozenset()
) -> CspDiff:
    added: dict[str, tuple[str, ...]] = {}
    removed: dict[str, tuple[str, ...]] = {}
    for name in sorted(set(before) & set(after)):
        plus = tuple(s for s in after[name] if s not in before[name] and s not in ignore)
        minus = tuple(s for s in before[name] if s not in after[name] and s not in ignore)
        if plus:
            added[name] = plus
        if minus:
            removed[name] = minus
    return CspDiff(
        directives_added=tuple(sorted(set(after) - set(before))),
        directives_removed=tuple(sorted(set(before) - set(after))),
        sources_added=added,
        sources_removed=removed,
    )
