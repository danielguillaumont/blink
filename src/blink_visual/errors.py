"""User-facing errors and the stable exit codes from BUILD_PLAN.md section 3."""

from __future__ import annotations

EXIT_OK = 0
"""Clean run, or the gate passed."""
EXIT_FINDINGS = 1
"""Findings at or above ``--fail-on``."""
EXIT_USAGE = 2
"""Usage, configuration or I/O error."""
EXIT_CAPTURE = 3
"""Capture failed: target unreachable or timed out."""


class BlinkError(Exception):
    """An actionable error shown to the user as ``blink: <message>``."""

    exit_code = EXIT_USAGE

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        return self.message if self.hint is None else f"{self.message}\nhint: {self.hint}"


class ConfigError(BlinkError):
    """``blink.yaml`` or another configuration file is missing or invalid."""


class StoreError(BlinkError):
    """The local evidence store is unreadable, corrupt or inconsistent."""


class CaptureError(BlinkError):
    """The target could not be captured (unreachable, timeout, browser failure)."""

    exit_code = EXIT_CAPTURE


class JourneyStepError(CaptureError):
    """A journey step failed, so the payment page was not reached and was not evaluated."""

    def __init__(
        self,
        message: str,
        *,
        step: int,
        action: str,
        description: str,
        url: str | None = None,
        screenshot: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint)
        self.step = step
        self.action = action
        self.description = description
        self.url = url
        self.screenshot = screenshot
        """Blob digest of a screenshot taken where the journey broke."""


class MissingExtraError(BlinkError):
    """An optional dependency group is not installed."""

    def __init__(self, extra: str, feature: str) -> None:
        super().__init__(
            f"{feature} needs the optional '{extra}' dependencies.",
            hint=f'install them with: python -m pip install "blink-checkout[{extra}]"',
        )
