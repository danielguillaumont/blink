"""Playwright Chromium capture driver (needs the ``[capture]`` extra).

Determinism: fixed viewport and user agent per profile, fixed locale and timezone,
``reducedMotion``, a light colour scheme, a stylesheet that disables animations and
transitions while screenshotting, masked volatile regions, a wait strategy of
load + network idle + an optional selector, then a short settle delay.

Privacy: form field *values* are never read; cookies are recorded by name and flags only;
credential and cookie headers are scrubbed from the HAR and dropped from the header set.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import secrets
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from ..config import ProfileConfig, TargetConfig
from ..errors import CaptureError, JourneyStepError, MissingExtraError
from ..journey.data import Resolver
from ..journey.runner import SUBMIT_GUARD_JS, JourneyRunner, StepFailed
from .access import install_header, resolve_access
from .har import SENSITIVE_HEADERS, scrub_har_bytes
from .models import (
    Box,
    CookieRecord,
    FormInput,
    FormRecord,
    IframeRecord,
    Initiator,
    JourneyRecord,
    JourneyState,
    RegionCapture,
    RequestRecord,
    ScriptRecord,
    Snapshot,
)
from .normalize import dom_hash, normalize_dom
from .tls import inspect_tls

if TYPE_CHECKING:
    from playwright.sync_api import (
        Browser,
        FloatRect,
        Frame,
        Page,
        Playwright,
        ProxySettings,
        Response,
    )

    from ..store import Store

MAX_SCRIPT_BYTES = 5 * 1024 * 1024
MAX_SCREENSHOT_HEIGHT = 8000
MASK_COLOR = "#FF00FF"
FREEZE_CSS = """
*, *::before, *::after {
  animation: none !important; transition: none !important; caret-color: transparent !important;
  scroll-behavior: auto !important;
}
"""
LAUNCH_ARGS = [
    "--force-color-profile=srgb",
    "--font-render-hinting=none",
    "--hide-scrollbars",
    "--disable-features=Translate,OptimizationHints,MediaRouter",
]

# Runs inside every frame. Reads attributes and geometry only, never field values.
COLLECT_JS = """
() => {
  const box = (el) => {
    const r = el.getBoundingClientRect();
    return {x: r.x + scrollX, y: r.y + scrollY, width: r.width, height: r.height};
  };
  const fields = 'input, select, textarea';
  const describe = (el) => ({
    name: el.getAttribute('name'),
    type: (el.tagName === 'INPUT' ? el.type : el.tagName).toLowerCase(),
    autocomplete: el.getAttribute('autocomplete'),
    id: el.id || null,
  });
  const scripts = Array.from(document.scripts).map((s) => ({
    src: s.hasAttribute('src') ? s.src : null,
    text: s.hasAttribute('src') ? null : s.textContent,
    integrity: s.getAttribute('integrity'),
    crossorigin: s.getAttribute('crossorigin'),
    type: s.getAttribute('type'),
  }));
  const forms = Array.from(document.forms).map((f) => ({
    action: f.hasAttribute('action') ? f.action : null,
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    id: f.id || null,
    name: f.getAttribute('name'),
    inputs: Array.from(f.querySelectorAll(fields)).map(describe),
    box: box(f),
  }));
  const orphans = Array.from(document.querySelectorAll(fields)).filter((el) => !el.form)
    .map(describe);
  const docW = Math.max(document.documentElement.scrollWidth, innerWidth);
  const docH = Math.max(document.documentElement.scrollHeight, innerHeight);
  const iframes = Array.from(document.querySelectorAll('iframe, frame')).map((f) => {
    const cs = getComputedStyle(f);
    const b = box(f);
    const hidden = cs.display === 'none' || cs.visibility === 'hidden' ||
      parseFloat(cs.opacity) === 0 || b.width <= 2 || b.height <= 2;
    const offscreen = b.x + b.width <= 0 || b.y + b.height <= 0 || b.x >= docW || b.y >= docH;
    return {
      src: f.hasAttribute('src') ? f.src : (f.hasAttribute('srcdoc') ? 'about:srcdoc' : null),
      name: f.getAttribute('name'), id: f.id || null, box: b,
      visible: !hidden && !offscreen, offscreen, sandbox: f.getAttribute('sandbox'),
    };
  });
  return {scripts, forms, orphans, iframes};
}
"""

BOXES_JS = """
(selectors) => selectors.map((s) => Array.from(document.querySelectorAll(s)).map((el) => {
  const r = el.getBoundingClientRect();
  return {x: r.x + scrollX, y: r.y + scrollY, width: r.width, height: r.height};
}))
"""


def _sri(data: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")


def new_snapshot_id(now: datetime) -> str:
    return f"{now:%Y%m%dT%H%M%S%f}Z-{secrets.token_hex(3)}"


def _box(data: Any) -> Box | None:
    if not isinstance(data, dict):
        return None
    return Box(
        x=round(float(data["x"]), 2),
        y=round(float(data["y"]), 2),
        width=round(float(data["width"]), 2),
        height=round(float(data["height"]), 2),
    )


def _input(data: dict[str, Any]) -> FormInput:
    return FormInput(
        name=data.get("name"),
        type=str(data.get("type") or "text"),
        autocomplete=data.get("autocomplete"),
        id=data.get("id"),
    )


def _initiator(params: dict[str, Any]) -> Initiator:
    raw = params.get("initiator") or {}
    frames: list[str] = []
    stack = raw.get("stack") or {}
    while stack and len(frames) < 10:
        for call in stack.get("callFrames", []):
            if len(frames) >= 10:
                break
            name = call.get("functionName") or "(anonymous)"
            frames.append(f"{name}@{call.get('url', '')}:{call.get('lineNumber', 0) + 1}")
        stack = stack.get("parent") or {}
    return Initiator(type=str(raw.get("type", "other")), url=raw.get("url"), stack=tuple(frames))


@dataclass
class _Recorder:
    """Collects browser events during one capture."""

    requests: list[RequestRecord] = field(default_factory=list)
    failed: set[str] = field(default_factory=set)
    script_responses: dict[str, tuple[Response, str]] = field(default_factory=dict)
    initiators: dict[str, Initiator] = field(default_factory=dict)
    document: Response | None = None
    """The latest main-frame document response (a journey navigates several times)."""

    def on_request(self, request: Any) -> None:
        try:
            frame_url: str | None = request.frame.url
        except Exception:  # detached or service-worker request
            frame_url = None
        self.requests.append(
            RequestRecord(
                url=request.url,
                method=request.method,
                resource_type=request.resource_type,
                frame_url=frame_url,
            )
        )

    def on_request_failed(self, request: Any) -> None:
        self.failed.add(request.url)

    def on_response(self, response: Response) -> None:
        with contextlib.suppress(Exception):  # a detached frame has no parent to ask about
            if response.request.is_navigation_request() and response.frame.parent_frame is None:
                self.document = response
        if response.request.resource_type == "script" and response.url not in self.script_responses:
            try:
                frame_url = response.frame.url
            except Exception:
                frame_url = ""
            self.script_responses[response.url] = (response, frame_url)

    def on_websocket(self, websocket: Any) -> None:
        self.requests.append(
            RequestRecord(url=websocket.url, method="GET", resource_type="websocket")
        )

    def on_cdp_request(self, params: dict[str, Any]) -> None:
        url = params.get("request", {}).get("url")
        if url and url not in self.initiators:
            self.initiators[url] = _initiator(params)


class _Deadline:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.end = time.monotonic() + seconds

    def remaining_ms(self, floor: float = 250.0) -> float:
        return max(floor, (self.end - time.monotonic()) * 1000)

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.end


_active = threading.local()

PROXY_ENV = "BLINK_PROXY"


def proxy_settings(environ: Mapping[str, str] | None = None) -> dict[str, str] | None:
    """Chromium proxy from ``BLINK_PROXY`` (e.g. ``http://proxy.internal:3128``).

    ``BLINK_PROXY_BYPASS`` is a comma-separated bypass list; ``BLINK_PROXY_USERNAME`` and
    ``BLINK_PROXY_PASSWORD`` hold credentials (kept out of the URL so they are never logged).
    """
    env = os.environ if environ is None else environ
    server = env.get(PROXY_ENV, "").strip()
    if not server:
        return None
    parts = urlsplit(server if "://" in server else f"http://{server}")
    if parts.scheme not in {"http", "https", "socks5"} or not parts.hostname:
        raise CaptureError(
            f"{PROXY_ENV} must look like http://host:port (got scheme {parts.scheme!r})",
            hint="see docs/runbooks/troubleshooting-capture.md",
        )
    if parts.username or parts.password:
        raise CaptureError(
            f"put proxy credentials in BLINK_PROXY_USERNAME / BLINK_PROXY_PASSWORD, not in "
            f"{PROXY_ENV}",
        )
    settings = {"server": f"{parts.scheme}://{parts.netloc}"}
    for key, name in (
        ("bypass", "BLINK_PROXY_BYPASS"),
        ("username", "BLINK_PROXY_USERNAME"),
        ("password", "BLINK_PROXY_PASSWORD"),
    ):
        value = env.get(name, "").strip()
        if value:
            settings[key] = value
    return settings


class Capturer:
    """Owns a Playwright Chromium instance; each capture uses a fresh browser context.

    Playwright's sync API allows one instance per thread, so a ``Capturer`` entered while
    another is active in the same thread reuses that browser instead of launching one.
    """

    def __init__(self, *, headless: bool = True) -> None:
        self.headless = headless
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._borrowed = False

    def __enter__(self) -> Capturer:
        outer: Capturer | None = getattr(_active, "capturer", None)
        if outer is not None and outer._browser is not None:
            self._browser, self._borrowed = outer._browser, True
            return self
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise MissingExtraError("capture", "Browser capture") from None
        self._playwright = sync_playwright().start()
        try:
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=LAUNCH_ARGS,
                proxy=cast("ProxySettings | None", proxy_settings()),
            )
        except PlaywrightError as exc:
            self._playwright.stop()
            self._playwright = None
            first = str(exc).strip().splitlines()[0] if str(exc).strip() else repr(exc)
            raise CaptureError(
                f"cannot launch Chromium: {first}",
                hint="run `python -m playwright install chromium` (add --with-deps on Linux)",
            ) from None
        _active.capturer = self
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._borrowed:
            self._browser, self._borrowed = None, False
            return
        if getattr(_active, "capturer", None) is self:
            _active.capturer = None
        if self._browser is not None:
            self._browser.close()
        if self._playwright is not None:
            self._playwright.stop()
        self._browser = self._playwright = None

    @property
    def browser(self) -> Browser:
        if self._browser is None:
            raise RuntimeError("Capturer is not started; use it as a context manager")
        return self._browser

    def capture(
        self, target: TargetConfig, profile_name: str, profile: ProfileConfig, store: Store
    ) -> Snapshot:
        """Capture ``target`` with ``profile`` and persist all artifacts to ``store``."""
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        started = datetime.now(UTC)
        deadline = _Deadline(target.timeout_s)
        warnings: list[str] = []
        recorder = _Recorder()
        access = resolve_access(target, profile_proxy=profile.proxy)
        resolver = Resolver(test_data=target.test_data, target=target.name)
        with tempfile.TemporaryDirectory(prefix="blink-har-") as tmp:
            har_path = Path(tmp) / "network.har"
            context = self.browser.new_context(
                viewport={"width": profile.viewport.width, "height": profile.viewport.height},
                user_agent=profile.user_agent,
                is_mobile=profile.is_mobile,
                has_touch=profile.has_touch,
                device_scale_factor=profile.device_scale_factor,
                locale=profile.locale,
                timezone_id=profile.timezone,
                reduced_motion="reduce",
                color_scheme="light",
                service_workers="block",
                record_har_path=str(har_path),
                record_har_content="omit",
                **access.context_options,
            )
            try:
                install_header(context, access)
                if target.journey and not target.test_mode:
                    context.add_init_script(SUBMIT_GUARD_JS)
                page = context.new_page()
                page.set_default_timeout(deadline.remaining_ms())
                cdp = context.new_cdp_session(page)
                cdp.on("Network.requestWillBeSent", recorder.on_cdp_request)
                cdp.send("Network.enable")
                page.on("request", recorder.on_request)
                page.on("requestfailed", recorder.on_request_failed)
                page.on("response", recorder.on_response)
                page.on("websocket", recorder.on_websocket)
                try:
                    response = page.goto(
                        target.url, wait_until="load", timeout=deadline.remaining_ms()
                    )
                except PlaywrightTimeout:
                    raise CaptureError(
                        f"timed out after {target.timeout_s:g}s loading {target.url}",
                        hint="check that the target is reachable, or raise timeout_s",
                    ) from None
                except PlaywrightError as exc:
                    reason = str(exc).strip().splitlines()[0]
                    raise CaptureError(
                        f"target unreachable: {target.url} ({reason})",
                        hint="see docs/runbooks/troubleshooting-capture.md",
                    ) from None
                args = (target, profile_name, recorder, deadline, warnings, store, started)
                if target.journey:
                    snapshot = self._journey(page, response, resolver, *args)
                else:
                    self._check_redirect(page, target, deadline)
                    snapshot = self._collect(page, response, *args)
            except PlaywrightTimeout:
                raise CaptureError(
                    f"timed out after {target.timeout_s:g}s capturing {target.url}"
                ) from None
            finally:
                context.close()
            har = (
                scrub_har_bytes(
                    har_path.read_bytes(),
                    names=access.secret_headers,
                    values=access.secret_values | resolver.secrets_used,
                )
                if har_path.exists()
                else b"{}"
            )
        blobs = dict(snapshot.blobs)
        blobs["har"] = store.put_blob(har, "application/json")
        tls = None
        parts = urlsplit(snapshot.final_url or target.url)
        if parts.scheme == "https" and parts.hostname:
            tls = inspect_tls(
                parts.hostname, parts.port or 443, timeout=min(10.0, target.timeout_s)
            )
        duration = int((datetime.now(UTC) - started).total_seconds() * 1000)
        from dataclasses import replace

        return replace(snapshot, blobs=blobs, tls=tls, duration_ms=duration)

    @staticmethod
    def _check_redirect(page: Page, target: TargetConfig, deadline: _Deadline) -> None:
        """Fail clearly when a payment page bounced us elsewhere (empty cart, no session)."""
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        wanted, landed = urlsplit(target.url), urlsplit(page.url)
        if (wanted.netloc, wanted.path.rstrip("/")) == (landed.netloc, landed.path.rstrip("/")):
            return
        selector = target.wait_for or target.payment_region
        if not selector:
            return
        try:
            page.wait_for_selector(
                selector, state="attached", timeout=min(3000.0, deadline.remaining_ms())
            )
            return
        except PlaywrightTimeout:
            pass
        raise CaptureError(
            f"{target.url} redirected to {page.url} and {selector!r} never appeared: the "
            "payment page probably needs a cart, a session or earlier checkout steps",
            hint=(
                f"add a `journey:` to target '{target.name}' that adds a product to the cart and "
                "fills the guest details first (see docs/journeys.md)"
            ),
        )

    def _journey(
        self,
        page: Page,
        response: Response | None,
        resolver: Resolver,
        target: TargetConfig,
        profile_name: str,
        recorder: _Recorder,
        deadline: _Deadline,
        warnings: list[str],
        store: Store,
        started: datetime,
    ) -> Snapshot:
        """Run the journey; the last ``capture`` step (or the end) is the snapshot's state."""
        from dataclasses import replace

        states: list[JourneyState] = []
        extra_frames: list[tuple[str, dict[str, Any]]] = []
        primary: dict[str, Any] = {}
        runner: JourneyRunner

        def collect_primary() -> Snapshot:
            return self._collect(
                page,
                recorder.document or response,
                target,
                profile_name,
                recorder,
                deadline,
                warnings,
                store,
                started,
                extra_frames=list(extra_frames),
                extra_masks=list(runner.filled),
            )

        def on_capture(name: str, is_primary: bool) -> None:
            if is_primary:
                primary["name"], primary["snapshot"] = name, collect_primary()
                return
            frames = [
                (frame.url, data)
                for frame in page.frames
                if (data := self._frame_data(frame, warnings)) is not None
            ]
            extra_frames.extend(frames)
            png = page.screenshot(
                full_page=False,
                animations="disabled",
                caret="hide",
                mask=[page.locator(s) for s in runner.filled],
                mask_color=MASK_COLOR,
                timeout=deadline.remaining_ms(),
            )
            dom = normalize_dom(page.content(), target.normalize)
            states.append(
                JourneyState(
                    name=name,
                    url=page.url,
                    screenshot=store.put_blob(png, "image/png"),
                    dom_hash=dom_hash(dom),
                    scripts=sum(len(data.get("scripts", [])) for _, data in frames),
                )
            )

        runner = JourneyRunner(
            page, target, resolver, remaining_ms=deadline.remaining_ms, on_capture=on_capture
        )
        try:
            steps = runner.run()
        except StepFailed as failed:
            shot = None
            try:
                shot = store.put_blob(page.screenshot(full_page=False, timeout=5000), "image/png")
            except Exception:  # the page may be gone; the finding still names the step
                warnings.append("could not screenshot the failed journey step")
            raise JourneyStepError(
                f"journey step {failed.index} ({failed.step.describe()}) failed on {page.url}: "
                f"{failed.reason}",
                step=failed.index,
                action=failed.step.action,
                description=failed.step.describe(),
                url=page.url,
                screenshot=shot,
                hint=(
                    "the checkout flow or a selector changed: look at the screenshot, then fix "
                    "the step in blink.yaml (see docs/journeys.md)"
                ),
            ) from None
        snapshot = primary.get("snapshot") or collect_primary()
        states.append(
            JourneyState(
                name=primary.get("name", "final"),
                url=snapshot.final_url,
                screenshot=snapshot.blobs.get("screenshot"),
                dom_hash=snapshot.dom_hash,
                scripts=len(snapshot.scripts),
                primary=True,
            )
        )
        blocked = 0
        if not target.test_mode:
            try:
                blocked = int(page.evaluate("() => window.__blinkBlockedSubmits || 0"))
            except Exception:
                blocked = 0
        notes = list(snapshot.warnings)
        if blocked:
            notes.append(
                f"blocked {blocked} payment form submission(s): target is not in test_mode"
            )
        record = JourneyRecord(
            steps=tuple(steps),
            states=tuple(states),
            test_mode=target.test_mode,
            blocked_submissions=blocked,
        )
        return replace(snapshot, journey=record, warnings=tuple(notes))

    def _collect(
        self,
        page: Page,
        response: Response | None,
        target: TargetConfig,
        profile_name: str,
        recorder: _Recorder,
        deadline: _Deadline,
        warnings: list[str],
        store: Store,
        started: datetime,
        *,
        extra_frames: list[tuple[str, dict[str, Any]]] | None = None,
        extra_masks: list[str] | None = None,
    ) -> Snapshot:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        try:
            page.wait_for_load_state("networkidle", timeout=min(10_000, deadline.remaining_ms()))
        except PlaywrightTimeout:
            warnings.append("network did not become idle; captured anyway")
        if target.wait_for:
            try:
                page.wait_for_selector(
                    target.wait_for, state="attached", timeout=deadline.remaining_ms()
                )
            except PlaywrightTimeout:
                warnings.append(f"wait_for selector {target.wait_for!r} never appeared")
        if target.settle_ms:
            page.wait_for_timeout(target.settle_ms)

        frames_data: list[tuple[str, dict[str, Any]]] = []
        for frame in page.frames:
            data = self._frame_data(frame, warnings)
            if data is not None:
                frames_data.append((frame.url, data))

        mask_selectors = list(target.masks) + [
            m for m in extra_masks or () if m not in target.masks
        ]
        mask_boxes: list[Box] = []
        if mask_selectors:
            for group in page.evaluate(BOXES_JS, mask_selectors):
                mask_boxes.extend(b for b in map(_box, group) if b is not None)
        masks = [page.locator(selector) for selector in mask_selectors]
        shot_kwargs: dict[str, Any] = {
            "animations": "disabled",
            "caret": "hide",
            "style": FREEZE_CSS,
            "mask": masks,
            "mask_color": MASK_COLOR,
            "timeout": deadline.remaining_ms(),
        }
        height = int(page.evaluate("() => document.documentElement.scrollHeight"))
        clip: FloatRect | None = None
        if height > MAX_SCREENSHOT_HEIGHT:
            width = page.viewport_size["width"] if page.viewport_size else 1280
            clip = {"x": 0, "y": 0, "width": width, "height": MAX_SCREENSHOT_HEIGHT}
            warnings.append(
                f"page is {height}px tall; screenshot clipped to {MAX_SCREENSHOT_HEIGHT}px"
            )
        screenshot = page.screenshot(full_page=True, clip=clip, **shot_kwargs)
        blobs = {"screenshot": store.put_blob(screenshot, "image/png")}

        region: RegionCapture | None = None
        if target.payment_region:
            locator = page.locator(target.payment_region).first
            if locator.count():
                region_box = _box(locator.bounding_box())
                try:
                    region_png = locator.screenshot(**shot_kwargs)
                    blobs["region_screenshot"] = store.put_blob(region_png, "image/png")
                except PlaywrightError as exc:
                    warnings.append(f"payment region screenshot failed: {exc}")
                region = RegionCapture(target.payment_region, True, region_box)
            else:
                region = RegionCapture(target.payment_region, False)
                warnings.append(f"payment region {target.payment_region!r} not found")

        normalized = normalize_dom(page.content(), target.normalize)
        blobs["dom"] = store.put_blob(normalized.encode("utf-8"), "text/html")
        # Scripts seen at earlier ``capture`` states of a journey count too (inventory, 6.4.3).
        scripts = self._scripts(frames_data + (extra_frames or []), recorder, store, warnings)
        forms, iframes = self._forms_and_iframes(frames_data)
        cookies = tuple(
            sorted(
                (
                    CookieRecord(
                        name=c["name"],
                        domain=c["domain"],
                        path=c["path"],
                        secure=bool(c["secure"]),
                        http_only=bool(c["httpOnly"]),
                        same_site=c.get("sameSite"),
                        session=c.get("expires", -1) == -1,
                    )
                    for c in page.context.cookies()
                ),
                key=lambda c: (c.domain, c.path, c.name),
            )
        )
        headers: dict[str, str] = {}
        if response is not None:
            headers = {
                name: value
                for name, value in sorted(response.all_headers().items())
                if name not in SENSITIVE_HEADERS
            }
        requests = tuple(
            RequestRecord(r.url, r.method, r.resource_type, r.frame_url, r.url in recorder.failed)
            for r in recorder.requests
        )
        viewport = page.viewport_size or {"width": 0, "height": 0}
        return Snapshot(
            id=new_snapshot_id(started),
            target=target.name,
            profile=profile_name,
            url=target.url,
            final_url=page.url,
            captured_at=started.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            duration_ms=0,
            status=response.status if response is not None else None,
            user_agent=page.evaluate("() => navigator.userAgent"),
            viewport=(int(viewport["width"]), int(viewport["height"])),
            dom_hash=dom_hash(normalized),
            headers=headers,
            scripts=scripts,
            requests=requests,
            forms=forms,
            iframes=iframes,
            cookies=cookies,
            blobs=blobs,
            payment_region=region,
            masks=tuple(mask_boxes),
            warnings=tuple(warnings),
        )

    @staticmethod
    def _frame_data(frame: Frame, warnings: list[str]) -> dict[str, Any] | None:
        from playwright.sync_api import Error as PlaywrightError

        if frame.is_detached():
            return None
        try:
            data: dict[str, Any] = frame.evaluate(COLLECT_JS)
        except PlaywrightError as exc:
            warnings.append(f"could not inspect frame {frame.url}: {str(exc).splitlines()[0]}")
            return None
        return data

    @staticmethod
    def _scripts(
        frames_data: list[tuple[str, dict[str, Any]]],
        recorder: _Recorder,
        store: Store,
        warnings: list[str],
    ) -> tuple[ScriptRecord, ...]:
        records: dict[str, ScriptRecord] = {}
        seen_external: set[str] = set()

        def body_of(url: str) -> tuple[bytes | None, int | None]:
            entry = recorder.script_responses.get(url)
            if entry is None:
                return None, None
            response, _ = entry
            try:
                body = response.body()
            except Exception:
                return None, response.status
            if len(body) > MAX_SCRIPT_BYTES:
                warnings.append(f"script {url} exceeds {MAX_SCRIPT_BYTES} bytes; hash only")
            return body, response.status

        def keep(body: bytes, label: str) -> str | None:
            """Store a script body; on hosts whose antivirus blocks the file, keep the hash only."""
            try:
                return store.put_blob(body, "text/javascript")
            except OSError as exc:
                warnings.append(
                    f"could not store the body of {label} ({exc.strerror or exc}); an antivirus "
                    "may have blocked it, which itself suggests malicious code; hash only"
                )
                return None

        def external(url: str, frame_url: str, attrs: dict[str, Any], in_dom: bool) -> None:
            body, status = body_of(url)
            digest = None
            if body is not None:
                digest = (
                    keep(body, url)
                    if len(body) <= MAX_SCRIPT_BYTES
                    else hashlib.sha256(body).hexdigest()
                )
            ok = body is not None and status is not None and status < 400
            records[url] = ScriptRecord(
                url=url,
                inline=False,
                frame_url=frame_url,
                sha384=_sri(body) if body is not None else None,
                sha256=digest,
                size=len(body) if body is not None else None,
                integrity=attrs.get("integrity"),
                crossorigin=attrs.get("crossorigin"),
                type=attrs.get("type"),
                in_dom=in_dom,
                loaded=ok and url not in recorder.failed,
                status=status,
                initiator=recorder.initiators.get(url),
            )

        for frame_url, data in frames_data:
            for item in data.get("scripts", []):
                src = item.get("src")
                if src:
                    if src not in seen_external:
                        seen_external.add(src)
                        external(src, frame_url, item, in_dom=True)
                    continue
                text = item.get("text") or ""
                body = text.encode("utf-8")
                record = ScriptRecord(
                    url=None,
                    inline=True,
                    frame_url=frame_url,
                    sha384=_sri(body),
                    sha256=keep(body, f"an inline script in {frame_url}"),
                    size=len(body),
                    type=item.get("type"),
                    initiator=Initiator(type="parser", url=frame_url),
                )
                records.setdefault(record.key, record)
        for url, (_, frame_url) in recorder.script_responses.items():
            if url not in seen_external:
                external(url, frame_url, {}, in_dom=False)
        return tuple(sorted(records.values(), key=lambda s: (s.inline, s.key)))

    @staticmethod
    def _forms_and_iframes(
        frames_data: list[tuple[str, dict[str, Any]]],
    ) -> tuple[tuple[FormRecord, ...], tuple[IframeRecord, ...]]:
        forms: list[FormRecord] = []
        iframes: list[IframeRecord] = []
        for frame_url, data in frames_data:
            for item in data.get("forms", []):
                forms.append(
                    FormRecord(
                        action=item.get("action"),
                        method=str(item.get("method") or "get"),
                        frame_url=frame_url,
                        id=item.get("id"),
                        name=item.get("name"),
                        inputs=tuple(_input(i) for i in item.get("inputs", [])),
                        box=_box(item.get("box")),
                    )
                )
            orphans = data.get("orphans") or []
            if orphans:
                forms.append(
                    FormRecord(
                        action=None,
                        method="none",
                        frame_url=frame_url,
                        inputs=tuple(_input(i) for i in orphans),
                        orphan=True,
                    )
                )
            for item in data.get("iframes", []):
                iframes.append(
                    IframeRecord(
                        src=item.get("src"),
                        frame_url=frame_url,
                        name=item.get("name"),
                        id=item.get("id"),
                        box=_box(item.get("box")),
                        visible=bool(item.get("visible", True)),
                        offscreen=bool(item.get("offscreen", False)),
                        sandbox=item.get("sandbox"),
                    )
                )
        return tuple(forms), tuple(iframes)
