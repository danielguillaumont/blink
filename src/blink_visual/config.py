"""Typed configuration for ``blink.yaml`` (pydantic v2).

The file is user-authored, so validation errors are turned into short, actionable
messages that name the offending field.
"""

from __future__ import annotations

import re
from datetime import timedelta
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


EnvName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$")


class ProxyConfig(_Model):
    """A per-target (or per-profile) browser proxy. Credentials come from environment variables."""

    server: str = Field(min_length=1, max_length=500)
    bypass: str | None = Field(default=None, max_length=2000)
    username_env: EnvName | None = None
    password_env: EnvName | None = None

    @field_validator("server")
    @classmethod
    def _proxy_url(cls, value: str) -> str:
        parts = urlsplit(value if "://" in value else f"http://{value}")
        if parts.scheme not in {"http", "https", "socks5"} or not parts.hostname:
            raise ValueError("proxy server must look like http://host:port")
        if parts.username or parts.password:
            raise ValueError("put proxy credentials in username_env / password_env, not the URL")
        return f"{parts.scheme}://{parts.netloc}"

    @model_validator(mode="after")
    def _pair(self) -> ProxyConfig:
        if (self.username_env is None) != (self.password_env is None):
            raise ValueError("set both username_env and password_env, or neither")
        return self


class BasicAuth(_Model):
    """HTTP basic auth, sent only to the target's own origin."""

    type: Literal["basic"]
    username_env: EnvName
    password_env: EnvName


class HeaderAuth(_Model):
    """A header token (e.g. a staging bypass token), sent only to the target's own origin."""

    type: Literal["header"]
    header: str = "Authorization"
    value_env: EnvName
    prefix: str = Field(default="", max_length=50)
    """Prepended to the value, e.g. ``"Bearer "``."""

    @field_validator("header")
    @classmethod
    def _header_name(cls, value: str) -> str:
        if not HEADER_NAME.match(value):
            raise ValueError(f"not a valid HTTP header name: {value!r}")
        if value.lower() in {"cookie", "host", "content-length"}:
            raise ValueError(f"{value} cannot be used for auth")
        return value


AuthConfig = Annotated[BasicAuth | HeaderAuth, Field(discriminator="type")]


class ProfileConfig(_Model):
    """A deterministic browser profile (viewport, UA, locale, timezone)."""

    viewport: Viewport
    user_agent: str = Field(min_length=1, max_length=500)
    is_mobile: bool = False
    has_touch: bool = False
    device_scale_factor: float = Field(default=1.0, ge=1.0, le=4.0)
    locale: str = "en-US"
    timezone: str = "UTC"
    proxy: ProxyConfig | None = None
    """Optional per-profile proxy (e.g. a regional egress); wins over the target's proxy."""


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


_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(s|m|h|d|w)\s*$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
SEVERITY_NAMES = ("info", "low", "medium", "high", "critical")


def parse_duration(value: str | float | int) -> timedelta:
    """``90`` (seconds), ``"30s"``, ``"15m"``, ``"6h"``, ``"1d"`` or ``"1w"``."""
    if isinstance(value, int | float):
        seconds = float(value)
    else:
        match = _DURATION.match(value)
        if match is None:
            raise ValueError(f"invalid duration {value!r}; use e.g. 30s, 15m, 6h, 1d or 1w")
        seconds = float(match.group(1)) * _UNITS[match.group(2)]
    if seconds < 0:
        raise ValueError("durations must not be negative")
    return timedelta(seconds=seconds)


Duration = Annotated[str | int | float, Field(description="e.g. 30s, 15m, 6h, 1d, 1w")]


class ScheduleConfig(_Model):
    """When ``blink daemon`` scans. Default weekly (PCI DSS 11.6.1); daily is recommended."""

    interval: Duration | None = None
    cron: str | None = None
    """Five-field crontab in UTC, e.g. ``"0 3 * * *"``; mutually exclusive with ``interval``."""
    jitter: Duration = "5m"
    retries: int = Field(default=2, ge=0, le=10)
    retry_backoff: Duration = "1m"
    max_gap: Duration | None = None
    """Longest acceptable time without a successful evaluation; default from the schedule."""

    @field_validator("interval", "jitter", "retry_backoff", "max_gap")
    @classmethod
    def _duration(cls, value: Duration | None) -> Duration | None:
        if value is not None:
            parse_duration(value)
        return value

    @field_validator("cron")
    @classmethod
    def _cron(cls, value: str | None) -> str | None:
        if value is not None:
            if len(value.split()) != 5:
                raise ValueError("cron must have five fields (minute hour day month weekday)")
            from .schedule import crontab_weekdays

            crontab_weekdays(value.split()[4])
        return value

    @model_validator(mode="after")
    def _one_trigger(self) -> ScheduleConfig:
        if self.interval is not None and self.cron is not None:
            raise ValueError("set either interval or cron, not both")
        if self.interval is not None and parse_duration(self.interval) < timedelta(minutes=1):
            raise ValueError("interval must be at least 1m")
        return self

    def merged(self, override: ScheduleConfig | None) -> ScheduleConfig:
        if override is None:
            return self
        update = {k: getattr(override, k) for k in override.model_fields_set}
        if "cron" in update and "interval" not in update:
            update["interval"] = None
        if "interval" in update and "cron" not in update:
            update["cron"] = None
        return self.model_copy(update=update)


class _SinkBase(_Model):
    name: Name
    min_severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    """Only alerts at or above this severity; default: ``alerts.min_severity``."""


class WebhookSink(_SinkBase):
    type: Literal["webhook"]
    url: str | None = None
    url_env: str | None = None
    """Environment variable holding the URL; preferred, because webhook URLs are secrets."""
    format: Literal["generic", "slack", "teams"] = "generic"
    timeout_s: float = Field(default=10, gt=0, le=120)

    @model_validator(mode="after")
    def _url(self) -> WebhookSink:
        if (self.url is None) == (self.url_env is None):
            raise ValueError("set exactly one of url or url_env")
        if self.url is not None:
            validate_url(self.url)
        return self


class SmtpSink(_SinkBase):
    type: Literal["smtp"]
    host: str
    port: int = Field(default=587, ge=1, le=65535)
    starttls: bool = True
    ssl: bool = False
    username_env: str | None = None
    password_env: str | None = None
    from_addr: str = Field(alias="from")
    to: list[str] = Field(min_length=1)
    timeout_s: float = Field(default=10, gt=0, le=120)

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class SyslogSink(_SinkBase):
    type: Literal["syslog"]
    host: str = "127.0.0.1"
    port: int = Field(default=514, ge=1, le=65535)
    protocol: Literal["udp", "tcp"] = "udp"
    facility: int = Field(default=13, ge=0, le=23)
    """Syslog facility number; 13 is "log audit"."""
    timeout_s: float = Field(default=5, gt=0, le=60)


class JsonlSink(_SinkBase):
    type: Literal["jsonl"]
    path: str
    """Relative paths resolve against the project directory."""


SinkConfig = Annotated[WebhookSink | SmtpSink | SyslogSink | JsonlSink, Field(discriminator="type")]


class AlertsConfig(_Model):
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    retries: int = Field(default=3, ge=0, le=10)
    backoff: Duration = "2s"
    dead_letter: str = "dead-letter.jsonl"
    """Undeliverable notifications, relative to the store directory."""
    sinks: list[SinkConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> AlertsConfig:
        names = [s.name for s in self.sinks]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate sink names: {', '.join(duplicates)}")
        parse_duration(self.backoff)
        return self


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
    schedule: ScheduleConfig | None = None
    """Overrides fields of the top-level ``schedule``."""
    proxy: ProxyConfig | None = None
    """Overrides ``BLINK_PROXY`` for this target."""
    auth: AuthConfig | None = None
    """Credentials for a protected (e.g. staging) target, read from environment variables."""

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
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    targets: list[TargetConfig] = Field(default_factory=list)

    def schedule_for(self, target: TargetConfig) -> ScheduleConfig:
        return self.schedule.merged(target.schedule)

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
