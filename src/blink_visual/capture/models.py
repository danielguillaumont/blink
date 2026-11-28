"""Value objects that make up a snapshot bundle.

A snapshot never contains cookie values, ``Authorization`` headers or form field values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

SNAPSHOT_SCHEMA_VERSION = 1


def origin_of(url: str | None) -> str | None:
    """``scheme://host[:port]`` for http(s)/ws(s) URLs, else ``None``."""
    if not url:
        return None
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https", "ws", "wss"} or not parts.hostname:
        return None
    default = {"http": 80, "https": 443, "ws": 80, "wss": 443}[parts.scheme]
    port = parts.port
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port is not None and port != default else ""
    return f"{parts.scheme}://{host}{suffix}"


@dataclass(frozen=True)
class Box:
    x: float
    y: float
    width: float
    height: float

    def intersects(self, other: Box) -> bool:
        return not (
            self.x + self.width <= other.x
            or other.x + other.width <= self.x
            or self.y + self.height <= other.y
            or other.y + other.height <= self.y
        )


@dataclass(frozen=True)
class Initiator:
    type: str
    url: str | None = None
    stack: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScriptRecord:
    """One script seen on the page: external (by URL) or inline (by content hash)."""

    url: str | None
    inline: bool
    frame_url: str
    sha384: str | None = None
    """SRI-formatted digest of the content (``sha384-<base64>``); ``None`` if never loaded."""
    sha256: str | None = None
    """Hex digest of the content; also the content-addressed blob key."""
    size: int | None = None
    integrity: str | None = None
    crossorigin: str | None = None
    type: str | None = None
    in_dom: bool = True
    loaded: bool = True
    status: int | None = None
    initiator: Initiator | None = None

    @property
    def key(self) -> str:
        """Stable identity: the URL for external scripts, the content digest for inline ones."""
        if self.inline or self.url is None:
            return f"inline:{self.sha384}"
        return self.url

    @property
    def origin(self) -> str | None:
        return origin_of(self.url)

    @property
    def is_javascript(self) -> bool:
        kind = (self.type or "").strip().lower()
        return kind in {"", "text/javascript", "application/javascript", "module"}


@dataclass(frozen=True)
class FormInput:
    name: str | None
    type: str
    autocomplete: str | None = None
    id: str | None = None

    @property
    def key(self) -> str:
        return f"{self.name or self.id or '?'}:{self.type}"


@dataclass(frozen=True)
class FormRecord:
    action: str | None
    method: str
    frame_url: str
    id: str | None = None
    name: str | None = None
    inputs: tuple[FormInput, ...] = ()
    orphan: bool = False
    """True for the pseudo-form that collects inputs outside any ``<form>``."""
    box: Box | None = None

    @property
    def key(self) -> str:
        if self.orphan:
            return f"{self.frame_url}#orphan-inputs"
        return f"{self.frame_url}#{self.id or self.name or 'form'}"


@dataclass(frozen=True)
class IframeRecord:
    src: str | None
    frame_url: str
    name: str | None = None
    id: str | None = None
    box: Box | None = None
    visible: bool = True
    offscreen: bool = False
    sandbox: str | None = None

    @property
    def key(self) -> str:
        return self.src or f"{self.frame_url}#iframe:{self.id or self.name or '?'}"


@dataclass(frozen=True)
class CookieRecord:
    """Cookie metadata only. Values are never captured."""

    name: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str | None = None
    session: bool = False


@dataclass(frozen=True)
class RequestRecord:
    url: str
    method: str
    resource_type: str
    frame_url: str | None = None
    failed: bool = False

    @property
    def origin(self) -> str | None:
        return origin_of(self.url)


@dataclass(frozen=True)
class TlsInfo:
    host: str
    port: int
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    fingerprint_sha256: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san: tuple[str, ...] = ()
    trusted: bool = False
    error: str | None = None


@dataclass(frozen=True)
class RegionCapture:
    selector: str
    found: bool
    box: Box | None = None


@dataclass(frozen=True)
class JourneyStepRecord:
    """One executed journey step. ``description`` holds templates, never resolved values."""

    index: int
    action: str
    description: str
    status: str
    """``ok``, ``failed`` or ``skipped``."""
    duration_ms: int = 0
    url: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class JourneyState:
    """A page state marked with a ``capture`` step."""

    name: str
    url: str
    screenshot: str | None = None
    dom_hash: str | None = None
    scripts: int = 0
    primary: bool = False
    """The state whose DOM, forms and screenshot are the snapshot's own."""


@dataclass(frozen=True)
class JourneyRecord:
    steps: tuple[JourneyStepRecord, ...] = ()
    states: tuple[JourneyState, ...] = ()
    test_mode: bool = False
    blocked_submissions: int = 0
    """Payment form submissions Blink blocked because the target is not in test_mode."""


@dataclass(frozen=True)
class Snapshot:
    """Manifest of one capture. Large artifacts are referenced by blob digest."""

    id: str
    target: str
    profile: str
    url: str
    final_url: str
    captured_at: str
    duration_ms: int
    status: int | None
    user_agent: str
    viewport: tuple[int, int]
    dom_hash: str
    headers: dict[str, str]
    scripts: tuple[ScriptRecord, ...]
    requests: tuple[RequestRecord, ...]
    forms: tuple[FormRecord, ...]
    iframes: tuple[IframeRecord, ...]
    cookies: tuple[CookieRecord, ...]
    blobs: dict[str, str]
    """Role → sha256 blob digest: ``dom``, ``screenshot``, ``region_screenshot``, ``har``."""
    tls: TlsInfo | None = None
    payment_region: RegionCapture | None = None
    masks: tuple[Box, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: int = SNAPSHOT_SCHEMA_VERSION
    meta: dict[str, str] = field(default_factory=dict)
    journey: JourneyRecord | None = None
