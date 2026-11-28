"""Typed configuration for ``blink.yaml`` (pydantic v2).

The file is user-authored, so validation errors are turned into short, actionable
messages that name the offending field.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigError

CONFIG_FILENAME = "blink.yaml"
NAME_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,62}$"

Name = Annotated[str, Field(pattern=NAME_PATTERN)]
Selector = Annotated[str, Field(min_length=1, max_length=500)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Viewport(_Model):
    width: int = Field(ge=200, le=4000)
    height: int = Field(ge=200, le=4000)


class ProfileConfig(_Model):
    """A deterministic browser profile (viewport, UA, locale, timezone)."""

    viewport: Viewport
    user_agent: str = Field(min_length=1, max_length=500)
    is_mobile: bool = False
    has_touch: bool = False
    device_scale_factor: float = Field(default=1.0, ge=1.0, le=4.0)
    locale: str = "en-US"
    timezone: str = "UTC"


class VolatileAttribute(_Model):
    selector: Selector
    attributes: list[str] = Field(min_length=1)


class RegexRule(_Model):
    pattern: str = Field(min_length=1, max_length=500)
    replacement: str = ""

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regular expression: {exc}") from exc
        return value


class NormalizeConfig(_Model):
    """How to make the captured DOM deterministic before hashing."""

    strip_attributes: list[str] = Field(default_factory=lambda: ["nonce"])
    volatile_attributes: list[VolatileAttribute] = Field(default_factory=list)
    volatile_text: list[Selector] = Field(default_factory=list)
    remove: list[Selector] = Field(default_factory=list)
    regexes: list[RegexRule] = Field(default_factory=list)


class VisualConfig(_Model):
    """Blink 1.0 engine settings for the payment-region visual detector."""

    threshold: int = Field(default=15, ge=0, le=255)
    min_region_pixels: int = Field(default=25, ge=1)
    min_change_percent: float = Field(default=0.05, ge=0, le=100)


class TargetConfig(_Model):
    name: Name
    url: str
    profiles: list[str] = Field(default_factory=lambda: ["desktop-chrome"], min_length=1)
    payment_region: Selector | None = None
    wait_for: Selector | None = None
    masks: list[Selector] = Field(default_factory=list)
    timeout_s: float = Field(default=30.0, gt=0, le=300)
    settle_ms: int = Field(default=250, ge=0, le=10_000)
    normalize: NormalizeConfig = Field(default_factory=NormalizeConfig)
    visual: VisualConfig = Field(default_factory=VisualConfig)

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        return validate_url(value)


class BlinkConfig(_Model):
    version: Literal[1] = 1
    store: str = ".blink"
    inventory: str = "blink.inventory.yaml"
    rules: str | None = None
    """Optional project rules file, evaluated before the packaged default rules."""
    profiles: dict[Name, ProfileConfig] = Field(default_factory=dict)
    targets: list[TargetConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> BlinkConfig:
        from .capture.profiles import BUILTIN_PROFILES

        names = [t.name for t in self.targets]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate target names: {', '.join(duplicates)}")
        known = set(BUILTIN_PROFILES) | set(self.profiles)
        for target in self.targets:
            unknown = [p for p in target.profiles if p not in known]
            if unknown:
                raise ValueError(
                    f"target '{target.name}' uses unknown profile(s) {', '.join(unknown)}; "
                    f"known profiles: {', '.join(sorted(known))}"
                )
        return self

    def target(self, name: str) -> TargetConfig:
        for target in self.targets:
            if target.name == name:
                return target
        known = ", ".join(t.name for t in self.targets) or "none configured"
        raise ConfigError(f"unknown target '{name}' (known: {known})")

    def profile(self, name: str) -> ProfileConfig:
        from .capture.profiles import BUILTIN_PROFILES

        if name in self.profiles:
            return self.profiles[name]
        if name in BUILTIN_PROFILES:
            return BUILTIN_PROFILES[name]
        raise ConfigError(f"unknown profile '{name}'")


def validate_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("must be an absolute http:// or https:// URL")
    return value


def _format_errors(error: ValidationError) -> str:
    lines = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "(root)"
        message = item["msg"].removeprefix("Value error, ")
        lines.append(f"  {location}: {message}")
    return "\n".join(lines)


def parse_config(data: Any, *, source: str = CONFIG_FILENAME) -> BlinkConfig:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top level")
    try:
        return BlinkConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{source} is invalid:\n{_format_errors(exc)}") from None


def load_config(path: Path) -> BlinkConfig:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ConfigError(
            f"configuration file not found: {path}", hint="run `blink init` to create one"
        ) from None
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from None
    return parse_config(data, source=str(path))
