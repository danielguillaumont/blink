"""Scripts detector: added, removed, changed content, inline injection and SRI problems."""

from __future__ import annotations

import base64
import hashlib

from ..capture.models import ScriptRecord
from ..errors import StoreError
from ..findings import Finding
from .base import DetectionContext

SRI_ALGORITHMS = ("sha256", "sha384", "sha512")


def parse_integrity(value: str) -> dict[str, set[str]]:
    """``{"sha384": {"<b64>", ...}}`` from an ``integrity`` attribute (options ignored)."""
    tokens: dict[str, set[str]] = {}
    for token in value.split():
        algorithm, _, rest = token.partition("-")
        algorithm = algorithm.lower()
        if algorithm in SRI_ALGORITHMS and rest:
            tokens.setdefault(algorithm, set()).add(rest.split("?", 1)[0])
    return tokens


def sri_matches(integrity: str, body: bytes) -> bool | None:
    """SRI verdict per the spec: only the strongest algorithm present is checked.
    ``None`` means the attribute has no usable token (browsers then skip the check)."""
    tokens = parse_integrity(integrity)
    strongest = next((a for a in reversed(SRI_ALGORITHMS) if a in tokens), None)
    if strongest is None:
        return None
    digest = base64.b64encode(hashlib.new(strongest, body).digest()).decode("ascii")
    return digest in tokens[strongest]


class ScriptsDetector:
    name = "scripts"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        before = {s.key: s for s in ctx.baseline.scripts}
        after = {s.key: s for s in ctx.current.scripts}
        page = ctx.page_origin
        main_frame = ctx.current.final_url
        findings: list[Finding] = []
        for key, script in after.items():
            old = before.get(key)
            cross = (not script.inline) and script.origin is not None and script.origin != page
            in_main = script.frame_url == main_frame
            if old is None:
                findings.append(self._added(script, cross, in_main))
            elif not script.inline and old.sha384 and script.sha384 and old.sha384 != script.sha384:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="hash_changed",
                        subject=key,
                        title=f"Content of {'third-party' if cross else 'first-party'} script "
                        f"changed: {key}",
                        attributes={
                            "cross_origin": cross,
                            "has_sri": bool(script.integrity),
                            "in_main_frame": in_main,
                        },
                        evidence={
                            "url": key,
                            "before_sha384": old.sha384,
                            "after_sha384": script.sha384,
                            "before_blob": old.sha256,
                            "after_blob": script.sha256,
                            "before_size": old.size,
                            "after_size": script.size,
                        },
                    )
                )
            if not script.inline and cross and script.is_javascript and not script.integrity:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="sri_missing",
                        subject=key,
                        title=f"Cross-origin script without Subresource Integrity: {key}",
                        attributes={"new": old is None, "in_main_frame": in_main},
                        evidence={"url": key, "sha384": script.sha384},
                    )
                )
            if script.integrity and not script.inline:
                verdict = self._verify(ctx, script)
                if verdict is False:
                    findings.append(
                        Finding(
                            detector=self.name,
                            change_type="sri_mismatch",
                            subject=key,
                            title=f"Script content does not match its integrity attribute: {key}",
                            attributes={"cross_origin": cross, "loaded": script.loaded},
                            evidence={
                                "url": key,
                                "integrity": script.integrity,
                                "actual_sha384": script.sha384,
                                "blob": script.sha256,
                            },
                        )
                    )
        for key, script in before.items():
            if key not in after:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="removed",
                        subject=key,
                        title=f"Script no longer present: {key[:120]}",
                        attributes={"inline": script.inline},
                        evidence={"sha384": script.sha384, "blob": script.sha256},
                    )
                )
        return findings

    def _added(self, script: ScriptRecord, cross: bool, in_main: bool) -> Finding:
        initiator = script.initiator
        evidence = {
            "url": script.url,
            "sha384": script.sha384,
            "blob": script.sha256,
            "size": script.size,
            "frame_url": script.frame_url,
            "integrity": script.integrity,
            "initiator": None
            if initiator is None
            else {"type": initiator.type, "url": initiator.url, "stack": list(initiator.stack)},
        }
        if script.inline:
            return Finding(
                detector=self.name,
                change_type="inline_added",
                subject=script.key,
                title=f"New inline script ({script.size or 0} bytes)",
                attributes={"inline": True, "in_main_frame": in_main, "size": script.size or 0},
                evidence=evidence,
            )
        kind = "third-party" if cross else "first-party"
        return Finding(
            detector=self.name,
            change_type="added",
            subject=script.key,
            title=f"New {kind} script: {script.key}",
            attributes={
                "cross_origin": cross,
                "has_sri": bool(script.integrity),
                "in_dom": script.in_dom,
                "loaded": script.loaded,
                "in_main_frame": in_main,
            },
            evidence=evidence,
        )

    @staticmethod
    def _verify(ctx: DetectionContext, script: ScriptRecord) -> bool | None:
        if script.integrity is None:
            return None
        tokens = parse_integrity(script.integrity)
        strongest = next((a for a in reversed(SRI_ALGORITHMS) if a in tokens), None)
        if strongest == "sha384" and script.sha384:
            return script.sha384.removeprefix("sha384-") in tokens["sha384"]
        if strongest is None or script.sha256 is None:
            return None
        try:
            body = ctx.store.get_blob(script.sha256)
        except StoreError:
            return None
        return sri_matches(script.integrity, body)
