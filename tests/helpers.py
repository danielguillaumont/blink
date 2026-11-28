"""Builders for synthetic snapshots used by detector unit tests (no browser, no network)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from blink_visual.capture.models import (
    Box,
    FormInput,
    FormRecord,
    IframeRecord,
    RegionCapture,
    RequestRecord,
    ScriptRecord,
    Snapshot,
)
from blink_visual.config import TargetConfig
from blink_visual.detect import DetectionContext
from blink_visual.store import Store

PAGE = "https://shop.example/checkout"
NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
CSP = (
    "script-src 'self' https://cdn.example 'sha256-abc'; object-src 'none'; frame-ancestors 'none'"
)
HEADERS = {
    "content-security-policy": CSP,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "payment=(self)",
}
CARD_FORM = FormRecord(
    action="https://shop.example/pay",
    method="post",
    frame_url=PAGE,
    id="checkout-form",
    inputs=(
        FormInput("csrf", "hidden"),
        FormInput("cardnumber", "text", "cc-number"),
        FormInput("cvc", "text", "cc-csc"),
    ),
    box=Box(400, 100, 400, 300),
)


def script(url: str | None, sha: str = "sha384-AAA", **kw: Any) -> ScriptRecord:
    return ScriptRecord(url=url, inline=url is None, frame_url=PAGE, sha384=sha, **kw)


def snapshot(**overrides: Any) -> Snapshot:
    base = Snapshot(
        id="snap-base",
        target="checkout",
        profile="desktop-chrome",
        url=PAGE,
        final_url=PAGE,
        captured_at="2026-11-27T12:00:00.000Z",
        duration_ms=1,
        status=200,
        user_agent="UA",
        viewport=(1280, 900),
        dom_hash="0" * 64,
        headers=dict(HEADERS),
        scripts=(
            script("https://shop.example/app.js", "sha384-APP"),
            script("https://cdn.example/w.js", "sha384-W", integrity="sha384-W"),
        ),
        requests=(
            RequestRecord(PAGE, "GET", "document"),
            RequestRecord("https://cdn.example/w.js", "GET", "script"),
        ),
        forms=(CARD_FORM,),
        iframes=(),
        cookies=(),
        blobs={},
        payment_region=RegionCapture("#payment", True, Box(380, 80, 440, 360)),
    )
    return replace(base, **overrides)


def context(
    store: Store,
    baseline: Snapshot,
    current: Snapshot,
    target: TargetConfig | None = None,
) -> DetectionContext:
    return DetectionContext(
        baseline=baseline,
        current=current,
        target=target or TargetConfig(name="checkout", url=PAGE, payment_region="#payment"),
        store=store,
        now=NOW,
    )


def iframe(
    src: str, *, visible: bool = True, offscreen: bool = False, box: Box | None = None
) -> IframeRecord:
    return IframeRecord(src=src, frame_url=PAGE, box=box, visible=visible, offscreen=offscreen)
