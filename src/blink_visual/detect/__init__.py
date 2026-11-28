"""Detectors compare a baseline snapshot with a current snapshot of the same target/profile."""

from __future__ import annotations

from ..findings import Finding
from .base import DetectionContext, Detector
from .dom import DomDetector
from .forms import FormsDetector
from .headers import HeadersDetector
from .network import NetworkDetector
from .scripts import ScriptsDetector
from .tls import TlsDetector
from .visual import VisualDetector

__all__ = ["DETECTORS", "DetectionContext", "Detector", "run_detectors"]

DETECTORS: tuple[Detector, ...] = (
    ScriptsDetector(),
    NetworkDetector(),
    HeadersDetector(),
    FormsDetector(),
    DomDetector(),
    VisualDetector(),
    TlsDetector(),
)


def run_detectors(
    ctx: DetectionContext, detectors: tuple[Detector, ...] = DETECTORS
) -> list[Finding]:
    """Run every detector. A crashing detector becomes a finding instead of hiding changes."""
    findings: list[Finding] = []
    for detector in detectors:
        try:
            found = detector.detect(ctx)
        except Exception as exc:
            found = [
                Finding(
                    detector="blink",
                    change_type="detector_failed",
                    subject=detector.name,
                    title=f"The {detector.name} detector failed: {type(exc).__name__}",
                    evidence={"error": str(exc)[:500]},
                )
            ]
        findings.extend(f.scoped(ctx.current.target, ctx.current.profile) for f in found)
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    return list(unique.values())
