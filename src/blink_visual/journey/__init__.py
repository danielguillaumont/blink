"""Synthetic checkout journeys: ordered browser steps that reach the payment page."""

from __future__ import annotations

from ..errors import JourneyStepError
from ..findings import Finding


def step_failed_finding(target: str, profile: str, error: JourneyStepError) -> Finding:
    """``journey.step_failed``: the payment page was not reached, so it was not evaluated."""
    evidence: dict[str, object] = {
        "step": error.step,
        "action": error.action,
        "description": error.description,
        "url": error.url,
        "error": error.message[:500],
    }
    if error.screenshot:
        evidence["screenshot_blob"] = error.screenshot
    return Finding(
        detector="journey",
        change_type="step_failed",
        subject=f"step {error.step}: {error.description}",
        title=f"Journey step {error.step} ({error.description}) failed for {target} [{profile}]",
        target=target,
        profile=profile,
        attributes={"step": error.step, "action": error.action},
        evidence=evidence,
    )
