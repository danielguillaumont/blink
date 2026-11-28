"""Execute a target's journey in a Playwright page.

The runner drives the page step by step. ``capture`` steps call back into the capturer, which
records page states. A failed step raises :class:`StepFailed`; the capturer turns that into a
:class:`~blink_visual.errors.JourneyStepError` with a screenshot of where the journey broke.
"""

from __future__ import annotations

import contextlib
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

from ..capture.models import JourneyStepRecord
from ..config import TargetConfig
from .data import Resolver
from .model import JourneyStep

DEFAULT_STEP_TIMEOUT_S = 10.0

# Installed before page scripts when a target is not in test_mode: a payment form (one with a
# card-like field) can't be submitted, whatever a step or a page script does. Only attribute
# names are inspected, never field values.
SUBMIT_GUARD_JS = r"""
(() => {
  const PAY = /cc-|card|cvc|cvv|csc|expir/i;
  const label = (el) => [el.getAttribute && el.getAttribute("autocomplete"), el.name, el.id]
    .filter(Boolean).join(" ");
  const isPayment = (form) =>
    !!form && Array.prototype.some.call(form.elements || [], (el) => PAY.test(label(el)));
  let blocked = 0;
  Object.defineProperty(window, "__blinkBlockedSubmits", { get: () => blocked });
  window.addEventListener("submit", (event) => {
    if (!isPayment(event.target)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    blocked++;
  }, true);
  const submit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    if (isPayment(this)) { blocked++; return undefined; }
    return submit.call(this);
  };
  const requestSubmit = HTMLFormElement.prototype.requestSubmit;
  if (requestSubmit) {
    HTMLFormElement.prototype.requestSubmit = function (submitter) {
      if (isPayment(this)) { blocked++; return undefined; }
      return requestSubmit.call(this, submitter);
    };
  }
})();
"""


class CheckFailed(Exception):
    """A step's own check failed (assert_url, assert_visible, an HTTP error on goto)."""


def _need(value: str | None) -> str:
    if value is None:  # pragma: no cover - the step model validates required fields
        raise CheckFailed("the step is missing a required field")
    return value


class StepFailed(Exception):
    def __init__(self, index: int, step: JourneyStep, reason: str, records: list[Any]) -> None:
        super().__init__(reason)
        self.index = index
        self.step = step
        self.reason = reason
        self.records = records


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip()
    first = text.splitlines()[0] if text else type(exc).__name__
    # Playwright prefixes "Locator.click: " etc.; keep the useful part.
    return re.sub(r"^\w+\.\w+:\s*", "", first)[:300]


class JourneyRunner:
    def __init__(
        self,
        page: Any,
        target: TargetConfig,
        resolver: Resolver,
        *,
        remaining_ms: Callable[[], float],
        on_capture: Callable[[str, bool], None],
    ) -> None:
        self.page = page
        self.target = target
        self.resolver = resolver
        self.remaining_ms = remaining_ms
        self.on_capture = on_capture
        self.records: list[JourneyStepRecord] = []
        self.filled: list[str] = []
        """Selectors of filled fields: their values change every run, so screenshots mask them."""

    def _timeout(self, step: JourneyStep) -> float:
        wanted = (step.timeout_s or DEFAULT_STEP_TIMEOUT_S) * 1000
        return max(250.0, min(wanted, self.remaining_ms()))

    def _scope(self, step: JourneyStep) -> Any:
        return self.page.frame_locator(step.frame) if step.frame else self.page

    def _locator(self, step: JourneyStep) -> Any:
        return self._scope(step).locator(_need(step.selector)).first

    def _settle(self, timeout: float) -> None:
        """After an action that may navigate, wait for the next document to load."""
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        with contextlib.suppress(PlaywrightTimeout):
            self.page.wait_for_load_state("load", timeout=min(timeout, 5000))

    def run(self) -> list[JourneyStepRecord]:
        from playwright.sync_api import Error as PlaywrightError

        steps = self.target.journey
        captures = [i for i, s in enumerate(steps, start=1) if s.action == "capture"]
        last_capture = captures[-1] if captures else None
        for index, step in enumerate(steps, start=1):
            started = time.monotonic()
            try:
                self._execute(index, step, primary=index == last_capture)
            except StepFailed:
                raise
            except PlaywrightError as exc:
                self._fail(index, step, _first_line(exc), started)
            except CheckFailed as exc:
                self._fail(index, step, str(exc), started)
            self.records.append(
                JourneyStepRecord(
                    index=index,
                    action=step.action,
                    description=step.describe(),
                    status="ok",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    url=self.page.url,
                )
            )
        return self.records

    def _fail(self, index: int, step: JourneyStep, reason: str, started: float) -> None:
        self.records.append(
            JourneyStepRecord(
                index=index,
                action=step.action,
                description=step.describe(),
                status="failed",
                duration_ms=int((time.monotonic() - started) * 1000),
                url=self.page.url,
                error=reason,
            )
        )
        for later, rest in enumerate(self.target.journey[index:], start=index + 1):
            self.records.append(
                JourneyStepRecord(later, rest.action, rest.describe(), status="skipped")
            )
        raise StepFailed(index, step, reason, self.records)

    def _execute(self, index: int, step: JourneyStep, *, primary: bool) -> None:
        timeout = self._timeout(step)
        action = step.action
        if action == "goto":
            url = urljoin(self.target.url, self.resolver.resolve(_need(step.url)))
            response = self.page.goto(url, wait_until="load", timeout=timeout)
            if response is not None and response.status >= 400:
                raise CheckFailed(f"HTTP {response.status} loading {step.url}")
        elif action in {"click", "submit"}:
            self._locator(step).click(timeout=timeout)
            self._settle(timeout)
        elif action == "fill":
            self._locator(step).fill(self.resolver.resolve(_need(step.value)), timeout=timeout)
            if step.frame is None and step.selector not in self.filled:
                self.filled.append(step.selector or "")
        elif action == "select":
            value = self.resolver.resolve(_need(step.value))
            locator = self._locator(step)
            try:
                locator.select_option(value=value, timeout=timeout)
            except Exception:
                locator.select_option(label=value, timeout=timeout)
        elif action == "check":
            self._locator(step).check(timeout=timeout)
        elif action == "press":
            key = _need(step.key)
            if step.selector:
                self._locator(step).press(key, timeout=timeout)
            else:
                self.page.keyboard.press(key)
            self._settle(timeout)
        elif action == "wait_for":
            self._locator(step).wait_for(state="visible", timeout=timeout)
        elif action == "wait_ms":
            self.page.wait_for_timeout(min(float(step.ms or 0), self.remaining_ms()))
        elif action == "assert_visible":
            try:
                self._locator(step).wait_for(state="visible", timeout=timeout)
            except Exception:
                raise CheckFailed(f"{step.selector!r} is not visible") from None
        elif action == "assert_url":
            self._assert_url(_need(step.url), timeout)
        elif action == "capture":
            self.on_capture(step.name or f"step-{index}", primary)

    def _assert_url(self, expected: str, timeout: float) -> None:
        if expected.startswith("re:"):
            pattern = re.compile(expected[3:])
            matches: Callable[[str], bool] = lambda url: bool(pattern.search(url))  # noqa: E731
        else:
            matches = lambda url: expected in url  # noqa: E731
        deadline = time.monotonic() + timeout / 1000
        while not matches(self.page.url):
            if time.monotonic() > deadline:
                raise CheckFailed(f"URL is {self.page.url}, expected it to contain {expected!r}")
            self.page.wait_for_timeout(100)
