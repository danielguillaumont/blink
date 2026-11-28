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


def lab_journey_target(shop_origin: str, *, name: str = "lab-journey") -> dict[str, Any]:
    """A target for the lab's multi-step flow: product -> cart -> guest details -> payment.

    ``/shop/checkout`` redirects to the cart unless the session has a cart and guest details,
    so it can only be reached with this journey. The journey stops at the payment form; it
    fills the card fields with the run's canary values but never submits them.
    """
    target = lab_target(f"{shop_origin.rstrip('/')}/shop/checkout", name=name)
    target["url"] = f"{shop_origin.rstrip('/')}/shop"
    target["test_data"] = {"email": "{{faker.email}}"}
    target["journey"] = [
        {"goto": "/shop"},
        {"click": "#add-to-cart"},
        {"wait_for": "#cart-items"},
        {"capture": "cart"},
        {"click": "#go-to-details"},
        {"fill": {"selector": "#email", "value": "{{test_data.email}}"}},
        {"fill": {"selector": "#full-name", "value": "{{canary.name}}"}},
        {"fill": {"selector": "#postcode", "value": "{{canary.postcode}}"}},
        {"select": {"selector": "#country", "value": "NL"}},
        {"check": "#terms"},
        {"click": "#continue-to-payment"},
        {"assert_url": "/shop/checkout"},
        {"wait_for": "#checkout-form"},
        {"fill": {"selector": "input[autocomplete=cc-number]", "value": "{{canary.pan}}"}},
        {"capture": "payment"},
    ]
    return target
