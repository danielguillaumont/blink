"""Authentication, CSRF and security headers for ``blink serve``.

- Every non-GET endpoint needs ``Authorization: Bearer <token>``. The token is generated on
  ``blink init`` (``.blink/blink.token``, mode 0600) or taken from ``$BLINK_TOKEN``.
- Browser requests (anything carrying Blink cookies) must also echo the CSRF token
  (double-submit: an HttpOnly ``SameSite=Strict`` cookie plus an ``X-CSRF-Token`` header).
- On loopback, GET pages are open. Bound to any other address, GET pages need a session
  cookie from ``/login`` (or the bearer token).
- Every response gets a strict CSP and the other headers Blink itself checks for, so Blink
  passes its own header detector (the dogfood test).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from ..apitoken import TOKEN_ENV, TOKEN_FILE, ensure_token, load_token, token_path

CSRF_COOKIE = "blink_csrf"
SESSION_COOKIE = "blink_session"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
OPEN_PATHS = frozenset({"/login", "/healthz", "/metrics"})
OPEN_PREFIXES = ("/static/",)

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "object-src 'none'"
)
SWAGGER_CDN = "https://cdn.jsdelivr.net"
DOCS_CSP = (
    f"default-src 'none'; script-src 'self' {SWAGGER_CDN}; style-src 'self' {SWAGGER_CDN}; "
    "img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; object-src 'none'"
)
HEADERS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "payment=(), camera=(), microphone=(), geolocation=(), usb=()",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host == "localhost"


@dataclass(frozen=True)
class Guard:
    token: str
    loopback: bool

    @property
    def session_value(self) -> str:
        return hmac.new(self.token.encode(), b"blink-session-v1", hashlib.sha256).hexdigest()

    def bearer_ok(self, request: Request) -> bool:
        header = request.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(value.strip(), self.token)

    def session_ok(self, request: Request) -> bool:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        return bool(cookie) and hmac.compare_digest(cookie, self.session_value)

    def token_ok(self, candidate: str) -> bool:
        return hmac.compare_digest(candidate.strip(), self.token)

    @staticmethod
    def csrf_ok(request: Request) -> bool:
        cookie = request.cookies.get(CSRF_COOKIE, "")
        sent = request.headers.get(CSRF_HEADER, "")
        return bool(cookie) and hmac.compare_digest(cookie, sent)

    @staticmethod
    def form_csrf_ok(request: Request, sent: str) -> bool:
        cookie = request.cookies.get(CSRF_COOKIE, "")
        return bool(cookie) and hmac.compare_digest(cookie, sent)

    @staticmethod
    def is_browser(request: Request) -> bool:
        return CSRF_COOKIE in request.cookies or SESSION_COOKIE in request.cookies


def _open(path: str) -> bool:
    return path in OPEN_PATHS or path.startswith(OPEN_PREFIXES)


def security_middleware(
    guard: Guard,
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    async def middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        response: Response
        if request.method not in SAFE_METHODS:
            if path == "/login":
                response = await call_next(request)  # checks its own form CSRF field
            elif not guard.bearer_ok(request):
                response = _error(401, "a bearer token is required for changes")
            elif Guard.is_browser(request) and not Guard.csrf_ok(request):
                response = _error(403, "CSRF check failed; reload the page and try again")
            else:
                response = await call_next(request)
        elif guard.loopback or _open(path) or guard.bearer_ok(request) or guard.session_ok(request):
            response = await call_next(request)
        elif path.startswith("/api/") or path == "/openapi.json":
            response = _error(401, "log in or send a bearer token")
        else:
            response = RedirectResponse("/login", status_code=303)
        _harden(request, response)
        return response

    return middleware


def _error(status: int, detail: str) -> Response:
    return JSONResponse({"detail": detail}, status_code=status)


def _harden(request: Request, response: Response) -> None:
    path = request.url.path
    response.headers["content-security-policy"] = DOCS_CSP if path == "/docs" else CSP
    for name, value in HEADERS.items():
        response.headers[name] = value
    if not path.startswith("/static/"):
        response.headers["cache-control"] = "no-store"
    is_html = response.headers.get("content-type", "").startswith("text/html")
    if is_html and CSRF_COOKIE not in request.cookies:
        token = getattr(request.state, "csrf", None) or secrets.token_urlsafe(24)
        response.set_cookie(
            CSRF_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )


def csrf_token(request: Request) -> str:
    """The CSRF token to render into the page (reuses the cookie, or mints the next one)."""
    existing = request.cookies.get(CSRF_COOKIE)
    if existing:
        return existing
    token: str | None = getattr(request.state, "csrf", None)
    if token is None:
        token = secrets.token_urlsafe(24)
        request.state.csrf = token
    return token


__all__ = [
    "TOKEN_ENV",
    "TOKEN_FILE",
    "Guard",
    "csrf_token",
    "ensure_token",
    "is_loopback",
    "load_token",
    "security_middleware",
    "token_path",
]
