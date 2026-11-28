"""TLS detector: certificate issuer or identity changes, trust loss and imminent expiry."""

from __future__ import annotations

from datetime import datetime

from ..capture.models import TlsInfo
from ..findings import Finding
from .base import DetectionContext

EXPIRY_WARNING_DAYS = 14


def _days_left(info: TlsInfo, now: datetime) -> float | None:
    if not info.not_after:
        return None
    return (datetime.fromisoformat(info.not_after) - now).total_seconds() / 86400


class TlsDetector:
    name = "tls"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        old, new = ctx.baseline.tls, ctx.current.tls
        if new is None:
            return []
        subject = f"{new.host}:{new.port}"
        findings: list[Finding] = []

        def add(change_type: str, title: str, attributes: dict[str, object] | None = None) -> None:
            findings.append(
                Finding(
                    detector=self.name,
                    change_type=change_type,
                    subject=subject,
                    title=title,
                    attributes=dict(attributes or {}),
                    evidence={
                        "before": None if old is None else _summary(old),
                        "after": _summary(new),
                    },
                )
            )

        if new.error:
            if old is None or not old.error:
                add("tls_error", f"TLS handshake failed: {new.error}")
            return findings
        if old is not None and not old.error:
            if old.issuer != new.issuer:
                add("issuer_changed", f"Certificate issuer changed to {new.issuer}")
            elif old.fingerprint_sha256 != new.fingerprint_sha256:
                add("certificate_changed", "Certificate changed (same issuer)")
            if old.trusted and not new.trusted:
                add("untrusted", "Certificate is no longer trusted")
        days = _days_left(new, ctx.now)
        if days is not None and days < EXPIRY_WARNING_DAYS:
            add(
                "expiring",
                f"Certificate expires in {max(days, 0):.1f} days",
                {"days_left": round(days, 1), "expired": days <= 0},
            )
        return findings


def _summary(info: TlsInfo) -> dict[str, object]:
    return {
        "subject": info.subject,
        "issuer": info.issuer,
        "fingerprint_sha256": info.fingerprint_sha256,
        "not_after": info.not_after,
        "trusted": info.trusted,
        "error": info.error,
    }
