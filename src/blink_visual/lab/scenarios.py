"""Lab tamper scenarios.

Each scenario changes exactly one aspect of the clean checkout so that Blink's detectors
can be tested deterministically. Fixtures are never functional skimmers: they never read
form values, never serialize payment inputs and only send the constant payload
``{"ping":1}`` to a localhost sink (``BUILD_PLAN.md`` section 5).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario("clean", "The known-good checkout, with benign rotating noise."),
        Scenario("new_third_party_script", "An extra cross-origin script without SRI."),
        Scenario("modified_approved_script", "The first-party app.js content changes."),
        Scenario("inline_script_injected", "An inert inline script is added to the payment area."),
        Scenario("csp_removed", "The Content-Security-Policy header is removed."),
        Scenario("csp_weakened_unsafe_inline", "script-src gains 'unsafe-inline'."),
        Scenario("form_action_changed", "The card form posts to another origin."),
        Scenario("hidden_iframe_added", "A 1x1 off-screen iframe from another origin."),
        Scenario("overlay_form_added", "A fake card form is drawn over the real one."),
        Scenario("new_beacon_destination", 'app.js beacons {"ping":1} to a new origin.'),
        Scenario("visual_payment_area_changed", "Payment button styling changes (CSS only)."),
        Scenario("noise_only", "Extra benign noise only; must produce no findings."),
    )
}

DEFAULT_SCENARIO = "clean"


def scenario_names() -> list[str]:
    return list(SCENARIOS)
