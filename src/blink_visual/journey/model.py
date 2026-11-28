"""The ``journey:`` section of a target: ordered steps, validated when ``blink.yaml`` loads.

Each step is written as a one-key mapping, the key being the action::

    journey:
      - goto: /shop
      - click: "#add-to-cart"
      - fill: {selector: "#email", value: "{{faker.email}}"}
      - wait_for: "#checkout-form"
      - capture: payment

Order safety: a ``submit`` step is only allowed when the target sets ``test_mode: true``, and
without it a ``click``/``press`` whose selector looks like placing the order is rejected (mark a
step ``safe: true`` when it is not the final submission, e.g. "continue to payment").
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .data import check_template

Action = Literal[
    "goto",
    "click",
    "fill",
    "select",
    "check",
    "press",
    "wait_for",
    "wait_ms",
    "assert_visible",
    "assert_url",
    "capture",
    "submit",
]
ACTIONS: tuple[str, ...] = Action.__args__  # type: ignore[attr-defined]
# The shorthand value of ``- action: VALUE`` fills this field.
SHORTHAND = {
    "goto": "url",
    "click": "selector",
    "fill": "selector",
    "select": "selector",
    "check": "selector",
    "press": "key",
    "wait_for": "selector",
    "wait_ms": "ms",
    "assert_visible": "selector",
    "assert_url": "url",
    "capture": "name",
    "submit": "selector",
}
NEEDS = {
    "goto": ("url",),
    "click": ("selector",),
    "fill": ("selector", "value"),
    "select": ("selector", "value"),
    "check": ("selector",),
    "press": ("key",),
    "wait_for": ("selector",),
    "wait_ms": ("ms",),
    "assert_visible": ("selector",),
    "assert_url": ("url",),
    "capture": (),
    "submit": ("selector",),
}
# Selectors that look like placing the order. Deliberately broad: a false positive costs one
# ``safe: true``; a false negative could place a real order.
ORDER_LIKE = re.compile(
    r"place[\s_-]?order|placeorder|pay[\s_-]?now|paynow|buy[\s_-]?now|complete[\s_-]?(order|purchase)"
    r"|confirm[\s_-]?(order|purchase|payment)|submit[\s_-]?(order|payment)|purchase|checkout[\s_-]?submit"
    r"|#pay\b|\bpay-button|button-pay|\[type=['\"]?submit",
    re.IGNORECASE,
)
STEP_NAME = r"^[a-z0-9][a-z0-9_-]{0,62}$"


class JourneyStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Action
    selector: str | None = Field(default=None, min_length=1, max_length=500)
    value: str | None = Field(default=None, max_length=2000)
    url: str | None = Field(default=None, min_length=1, max_length=2000)
    key: str | None = Field(default=None, min_length=1, max_length=50)
    ms: int | None = Field(default=None, ge=0, le=60_000)
    name: str | None = Field(default=None, pattern=STEP_NAME)
    frame: str | None = Field(default=None, min_length=1, max_length=500)
    """Selector of the iframe the step acts in (e.g. a hosted payment field)."""
    timeout_s: float | None = Field(default=None, gt=0, le=120)
    safe: bool = False
    """Declares that a click/press whose selector looks like placing the order is not one."""

    @model_validator(mode="before")
    @classmethod
    def _shorthand(cls, data: Any) -> Any:
        if not isinstance(data, dict) or "action" in data:
            return data
        actions = [k for k in data if k in ACTIONS]
        if len(actions) != 1:
            raise ValueError(
                f"each step needs exactly one action (one of: {', '.join(ACTIONS)}); "
                f"got {sorted(data) or 'nothing'}"
            )
        action = actions[0]
        rest = {k: v for k, v in data.items() if k != action}
        value = data[action]
        if isinstance(value, dict):
            overlap = set(value) & set(rest)
            if overlap:
                raise ValueError(f"{', '.join(sorted(overlap))} given twice in a {action} step")
            return {"action": action, **value, **rest}
        if value is None:
            return {"action": action, **rest}
        return {"action": action, SHORTHAND[action]: value, **rest}

    @model_validator(mode="after")
    def _complete(self) -> JourneyStep:
        missing = [f for f in NEEDS[self.action] if getattr(self, f) is None]
        if missing:
            raise ValueError(f"a {self.action} step needs {' and '.join(missing)}")
        return self

    def describe(self) -> str:
        """A short label for logs and findings (templates, never resolved values)."""
        detail = self.selector or self.url or self.key or (f"{self.ms}ms" if self.ms else "")
        where = f" in frame {self.frame}" if self.frame else ""
        label = f"{self.action} {detail}".strip()
        return f"{label}{where}" + (f" ({self.name})" if self.name else "")

    @property
    def looks_like_order_submission(self) -> bool:
        return self.action in {"click", "press"} and bool(
            self.selector and ORDER_LIKE.search(self.selector)
        )


def validate_journey(
    steps: list[JourneyStep], *, test_mode: bool, test_data: dict[str, str], target: str
) -> None:
    """Cross-step checks; raises ``ValueError`` with a message naming the step."""
    keys = set(test_data)
    for key, value in test_data.items():
        try:
            check_template(value, None)
        except ValueError as exc:
            raise ValueError(f"test_data.{key}: {exc}") from None
    names: set[str] = set()
    for number, step in enumerate(steps, start=1):
        where = f"journey step {number} ({step.action})"
        for text in (step.value, step.url):
            if text is not None:
                try:
                    check_template(text, keys)
                except ValueError as exc:
                    raise ValueError(f"{where}: {exc}") from None
        if step.action == "submit" and not test_mode:
            raise ValueError(
                f"{where}: a submit step places an order; it is only allowed when the target "
                f"'{target}' sets test_mode: true (a staging store with a test payment gateway)"
            )
        if step.looks_like_order_submission and not test_mode and not step.safe:
            raise ValueError(
                f"{where}: selector {step.selector!r} looks like the final order submission. "
                "Journeys must stop before placing an order: end the journey before this step, "
                "use `submit` on a test_mode: true target, or add `safe: true` if this step "
                "does not place an order"
            )
        if step.action == "capture":
            name = step.name or f"step-{number}"
            if name in names:
                raise ValueError(f"{where}: duplicate capture name '{name}'")
            names.add(name)
