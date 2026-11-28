"""Headers detector: security header policy checks plus a diff against the baseline."""

from __future__ import annotations

import re
from typing import Any

from ..findings import Finding
from .base import DetectionContext
from .csp import WEAKNESS_TOKENS, WILDCARD_SOURCES, diff_csp, parse_csp, script_policy, weaknesses

CSP = "content-security-policy"
HSTS = "strict-transport-security"
XFO = "x-frame-options"
XCTO = "x-content-type-options"
REFERRER = "referrer-policy"
PERMISSIONS = "permissions-policy"
OTHER_HEADERS = (HSTS, XFO, XCTO, REFERRER, PERMISSIONS)
SECURITY_HEADERS = (CSP, *OTHER_HEADERS)

HSTS_MIN_AGE = 15_552_000  # 180 days
WEAK_REFERRERS = frozenset({"unsafe-url", "no-referrer-when-downgrade"})
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def _hsts(value: str) -> tuple[int, bool]:
    match = _MAX_AGE.search(value)
    return (int(match.group(1)) if match else 0, "includesubdomains" in value.lower())


def _is_weakened(header: str, before: str, after: str) -> bool:
    """True when ``after`` is a weaker setting than ``before`` for ``header``."""
    b, a = before.strip().lower(), after.strip().lower()
    if header == HSTS:
        (old_age, old_sub), (new_age, new_sub) = _hsts(b), _hsts(a)
        return new_age < min(old_age, HSTS_MIN_AGE) or (old_sub and not new_sub)
    if header == XFO:
        rank = {"deny": 2, "sameorigin": 1}
        return rank.get(a, 0) < rank.get(b, 0)
    if header == XCTO:
        return b == "nosniff" and a != "nosniff"
    if header == REFERRER:
        return a.split(",")[-1].strip() in WEAK_REFERRERS
    if header == PERMISSIONS:
        payment = re.search(r"payment=\(([^)]*)\)", a)
        return bool(payment and "*" in payment.group(1))
    return False


def _frame_ancestors(headers: dict[str, str]) -> bool:
    value = headers.get(CSP)
    return bool(value) and "frame-ancestors" in parse_csp(value or "")


class HeadersDetector:
    name = "headers"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        before = {k.lower(): v for k, v in ctx.baseline.headers.items()}
        after = {k.lower(): v for k, v in ctx.current.headers.items()}
        findings = self._csp(before.get(CSP), after.get(CSP))
        covered = _frame_ancestors(after)
        for header in OTHER_HEADERS:
            old, new = before.get(header), after.get(header)
            attributes: dict[str, Any] = {"header": header}
            if header == XFO:
                attributes["covered_by_csp"] = covered
            if old is not None and new is None:
                findings.append(
                    self._finding(
                        "header_removed",
                        header,
                        f"{header} header removed",
                        attributes,
                        {"before": old},
                    )
                )
            elif old is None and new is not None:
                findings.append(
                    self._finding(
                        "header_added",
                        header,
                        f"{header} header added",
                        attributes,
                        {"after": new},
                    )
                )
            elif old is not None and new is not None and old.strip() != new.strip():
                attributes["weakened"] = _is_weakened(header, old, new)
                findings.append(
                    self._finding(
                        "header_changed",
                        header,
                        f"{header} changed",
                        attributes,
                        {"before": old, "after": new},
                    )
                )
            elif old is None and new is None and not (header == XFO and covered):
                findings.append(
                    self._finding(
                        "header_missing", header, f"{header} header is not set", attributes, {}
                    )
                )
        return findings

    def _finding(
        self,
        change_type: str,
        subject: str,
        title: str,
        attributes: dict[str, Any],
        evidence: dict[str, Any],
    ) -> Finding:
        return Finding(
            detector=self.name,
            change_type=change_type,
            subject=subject,
            title=title,
            attributes=attributes,
            evidence=evidence,
        )

    def _csp(self, before: str | None, after: str | None) -> list[Finding]:
        if before is None and after is None:
            return [self._finding("csp_missing", CSP, "No Content-Security-Policy header", {}, {})]
        if before is not None and after is None:
            had_policy = script_policy(parse_csp(before)) is not None
            return [
                self._finding(
                    "csp_removed",
                    CSP,
                    "Content-Security-Policy header removed",
                    {"had_script_policy": had_policy},
                    {"before": before},
                )
            ]
        if after is None:  # pragma: no cover - both-None and removed are handled above
            return []
        new = parse_csp(after)
        if before is None:
            return [
                self._finding(
                    "header_added",
                    CSP,
                    "Content-Security-Policy header added",
                    {"header": CSP},
                    {"after": after},
                )
            ]
        old = parse_csp(before)
        findings: list[Finding] = []
        old_weak, new_weak = weaknesses(old), weaknesses(new)
        for weakness in sorted(new_weak - old_weak):
            findings.append(
                self._finding(
                    "csp_weakened",
                    f"{CSP}:{weakness}",
                    f"Content-Security-Policy weakened: {weakness}",
                    {"weakness": weakness},
                    {"before": before, "after": after},
                )
            )
        for weakness in sorted(new_weak & old_weak):
            findings.append(
                self._finding(
                    "csp_weakness",
                    f"{CSP}:{weakness}",
                    f"Content-Security-Policy has a pre-existing weakness: {weakness}",
                    {"weakness": weakness},
                    {"after": after},
                )
            )
        ignore = frozenset(WEAKNESS_TOKENS.values()) | WILDCARD_SOURCES
        diff = diff_csp(old, new, ignore=ignore)
        if not diff.empty:
            script_added = sum(
                len(diff.sources_added.get(d, ())) for d in ("script-src", "default-src")
            )
            findings.append(
                self._finding(
                    "csp_changed",
                    CSP,
                    "Content-Security-Policy directives changed",
                    {
                        "script_sources_added": script_added,
                        "directives_removed": len(diff.directives_removed),
                        "script_directive_removed": bool(
                            {"script-src", "default-src"} & set(diff.directives_removed)
                        ),
                    },
                    {
                        "directives_added": list(diff.directives_added),
                        "directives_removed": list(diff.directives_removed),
                        "sources_added": {k: list(v) for k, v in diff.sources_added.items()},
                        "sources_removed": {k: list(v) for k, v in diff.sources_removed.items()},
                        "before": before,
                        "after": after,
                    },
                )
            )
        return findings
