"""Local demo shop with deterministic tamper scenarios (needs the ``[server]`` extra).

Loopback-only and test-only. See ``BUILD_PLAN.md`` section 5 for the safety rules.
"""

from __future__ import annotations

from typing import Any

from .scenarios import DEFAULT_SCENARIO, SCENARIOS, Scenario, scenario_names

__all__ = ["DEFAULT_SCENARIO", "SCENARIOS", "Scenario", "lab_target", "scenario_names"]


def lab_target(checkout_url: str, *, name: str = "lab-checkout") -> dict[str, Any]:
    """The ``blink.yaml`` target entry that matches the lab's volatile elements."""
    return {
        "name": name,
        "url": checkout_url,
        "profiles": ["desktop-chrome", "mobile-safari-ish"],
        "payment_region": "#payment",
        "wait_for": "#checkout-form",
        "masks": [".timestamp", ".promo"],
        "timeout_s": 30,
        "normalize": {
            "volatile_attributes": [
                {"selector": 'input[name="csrf_token"]', "attributes": ["value"]},
                {"selector": 'meta[name="csrf-token"]', "attributes": ["content"]},
                {"selector": "body", "attributes": ["data-render-id"]},
                {"selector": "img.lab-pixel", "attributes": ["src"]},
            ],
            "volatile_text": [".timestamp", ".promo"],
        },
    }
