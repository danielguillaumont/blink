"""The lab shop (FastAPI): a checkout page, a simulated third-party CDN and a localhost sink.

Three apps are served on three loopback ports so that the CDN and sink are genuinely
cross-origin relative to the shop.
"""

from __future__ import annotations

import base64
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from string import Template
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from .fixtures import INLINE_CONFIG, asset, sri
from .scenarios import DEFAULT_SCENARIO, SCENARIOS

PROMOS = (
    "Free shipping on orders over EUR 50 this week only.",
    "Members save 10 percent today. Sign in at checkout.",
    "New notebooks in stock. Limited colours available.",
)
INJECTED_INLINE = (
    "/* LAB FIXTURE: inert injected inline script */ window.__blinkLabInjected = true;"
)
OVERLAY = (
    '<div class="lab-overlay"><form action="#" class="lab-overlay-form">'
    "<p>Verify your card to continue</p>"
    '<input name="card_number" autocomplete="cc-number" placeholder="4242 4242 4242 4242">'
    '<input name="card_cvc" autocomplete="cc-csc" placeholder="123">'
    '<button type="button">Continue</button></form></div>'
)
# Lab-only credentials for /staging/checkout (not secrets: they protect nothing real).
LAB_BASIC_USER = "lab"
LAB_BASIC_PASSWORD = "lab-staging-pass"  # nosec B105
LAB_TOKEN_HEADER = "X-Lab-Token"
LAB_TOKEN = "lab-staging-token"  # nosec B105
AUTH_HEADERS = ("authorization", LAB_TOKEN_HEADER.lower())
# A transparent 1x1 GIF.
PIXEL = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


@dataclass
class LabState:
    """Mutable lab state shared by the three apps."""

    shop_origin: str
    cdn_origin: str
    sink_origin: str
    scenario: str = DEFAULT_SCENARIO
    leaked_auth: list[str] = field(default_factory=list)
    """Auth headers that reached the CDN or sink (they must only ever go to the shop)."""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_scenario(self, name: str) -> None:
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario '{name}'")
        with self._lock:
            self.scenario = name


def _csp(state: LabState, scenario: str) -> str | None:
    if scenario == "csp_removed":
        return None
    sources = ["'self'", state.cdn_origin, f"'{sri(INLINE_CONFIG, 'sha256')}'"]
    if scenario == "csp_weakened_unsafe_inline":
        sources.append("'unsafe-inline'")
    return (
        f"script-src {' '.join(sources)}; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'"
    )


def _security_headers(state: LabState, scenario: str) -> dict[str, str]:
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "payment=(self), camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store",
    }
    csp = _csp(state, scenario)
    if csp is not None:
        headers["Content-Security-Policy"] = csp
    return headers


def render_checkout(state: LabState, scenario: str) -> str:
    extra_head = payment_extra = body_extra = ""
    form_action = "/pay"
    stylesheet = "style.css"
    if scenario == "new_third_party_script":
        extra_head = f'<script src="{state.cdn_origin}/lib/analytics.js" defer></script>'
    elif scenario == "inline_script_injected":
        payment_extra = f"<script>{INJECTED_INLINE}</script>"
    elif scenario == "form_action_changed":
        form_action = f"{state.sink_origin}/pay"
    elif scenario == "hidden_iframe_added":
        body_extra = (
            f'<iframe src="{state.sink_origin}/frame" width="1" height="1" title="lab" '
            'style="position:absolute;left:-9999px;top:0;border:0"></iframe>'
        )
    elif scenario == "overlay_form_added":
        payment_extra = OVERLAY
    elif scenario == "visual_payment_area_changed":
        stylesheet = "style_changed.css"
    # A same-origin pixel exists in every scenario; noise_only rotates its cache-buster.
    cache_buster = secrets.token_hex(8) if scenario == "noise_only" else "0"
    body_extra += f'<img class="lab-pixel" alt="" src="/static/pixel.gif?cb={cache_buster}">'
    csrf = secrets.token_hex(16)
    return Template(asset("checkout.html")).substitute(
        csrf=csrf,
        stylesheet=stylesheet,
        inline_config=INLINE_CONFIG,
        cdn=state.cdn_origin,
        widget_integrity=sri(asset("widget.js")),
        extra_head=extra_head,
        render_id=secrets.token_hex(6),
        timestamp=datetime.now(UTC).isoformat(timespec="microseconds"),
        promo=secrets.choice(PROMOS),
        form_action=form_action,
        payment_extra=payment_extra,
        body_extra=body_extra,
    )


def _js(content: str, *, cors: bool = False) -> Response:
    headers = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    if cors:
        headers["Access-Control-Allow-Origin"] = "*"
    return Response(content, media_type="application/javascript", headers=headers)


def _bare_app(title: str) -> FastAPI:
    return FastAPI(title=title, docs_url=None, redoc_url=None, openapi_url=None)


def _watch_for_auth(app: FastAPI, state: LabState, origin: str) -> None:
    """Record (by header name only) any auth header sent to a third-party lab origin."""

    @app.middleware("http")
    async def watch(request: Request, call_next: Any) -> Response:
        for name in AUTH_HEADERS:
            if name in request.headers:
                state.leaked_auth.append(f"{origin}{request.url.path} {name}")
        response: Response = await call_next(request)
        return response


def _authorized(request: Request) -> bool:
    expected = "Basic " + base64.b64encode(
        f"{LAB_BASIC_USER}:{LAB_BASIC_PASSWORD}".encode()
    ).decode("ascii")
    return secrets.compare_digest(
        request.headers.get("authorization", ""), expected
    ) or secrets.compare_digest(request.headers.get(LAB_TOKEN_HEADER, ""), LAB_TOKEN)


def build_shop(state: LabState) -> FastAPI:
    app = _bare_app("Blink lab shop")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return '<!doctype html><title>Blink lab</title><a href="/checkout">Checkout</a>'

    @app.get("/checkout")
    def checkout() -> Response:
        scenario = state.scenario
        headers = _security_headers(state, scenario)
        if scenario == "noise_only":
            headers["X-Request-Id"] = secrets.token_hex(8)
            headers["ETag"] = f'"{secrets.token_hex(8)}"'
        response = HTMLResponse(render_checkout(state, scenario), headers=headers)
        # Cookie values rotate; Blink records only names and flags, never values.
        response.set_cookie("lab_session", secrets.token_hex(12), httponly=True, samesite="lax")
        return response

    @app.get("/staging/checkout")
    def staging_checkout(request: Request) -> Response:
        """The same checkout behind basic auth or a header token (``auth:`` in blink.yaml)."""
        if not _authorized(request):
            return PlainTextResponse(
                "authentication required",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="blink-lab"'},
            )
        return checkout()

    @app.get("/static/app.js")
    def app_js() -> Response:
        name = "app_modified.js" if state.scenario == "modified_approved_script" else "app.js"
        return _js(asset(name))

    @app.get("/static/{name}.css")
    def stylesheet(name: str) -> Response:
        if name not in {"style", "style_changed"}:
            raise HTTPException(404)
        return Response(asset(f"{name}.css"), media_type="text/css")

    @app.get("/static/pixel.gif")
    def pixel() -> Response:
        return Response(PIXEL, media_type="image/gif", headers={"Cache-Control": "no-store"})

    @app.get("/api/config")
    def config() -> JSONResponse:
        data: dict[str, str] = {"currency": "EUR"}
        if state.scenario == "new_beacon_destination":
            data["beacon_url"] = f"{state.sink_origin}/collect"
        return JSONResponse(data, headers={"Cache-Control": "no-store"})

    @app.post("/pay")
    def pay() -> PlainTextResponse:
        # Never read or store the request body: the lab does not process payments.
        return PlainTextResponse("The Blink lab does not process payments.")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "scenario": state.scenario}

    @app.get("/__admin/scenario")
    def get_scenario() -> dict[str, object]:
        return {"scenario": state.scenario, "scenarios": list(SCENARIOS)}

    @app.post("/__admin/scenario")
    def set_scenario(scenario: str) -> dict[str, object]:
        try:
            state.set_scenario(scenario)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"scenario": state.scenario, "scenarios": list(SCENARIOS)}

    return app


def build_cdn(state: LabState) -> FastAPI:
    app = _bare_app("Blink lab CDN")
    _watch_for_auth(app, state, state.cdn_origin)

    @app.get("/lib/widget.js")
    def widget() -> Response:
        return _js(asset("widget.js"), cors=True)

    @app.get("/lib/analytics.js")
    def analytics() -> Response:
        return _js(asset("analytics.js"), cors=True)

    return app


def build_sink(state: LabState) -> FastAPI:
    app = _bare_app("Blink lab sink")
    _watch_for_auth(app, state, state.sink_origin)
    cors = {"Access-Control-Allow-Origin": "*"}

    @app.post("/collect")
    def collect(request: Request) -> Response:
        # The body is deliberately never read: fixtures only ever send {"ping":1}.
        return Response(status_code=204, headers=cors)

    @app.post("/pay")
    def pay() -> PlainTextResponse:
        return PlainTextResponse("lab sink", headers=cors)

    @app.get("/frame", response_class=HTMLResponse)
    def frame() -> str:
        return asset("frame.html")

    return app
