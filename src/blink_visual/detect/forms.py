"""Forms detector: form actions, methods, inputs and iframes (including hidden overlays)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..capture.models import Box, FormInput, FormRecord, IframeRecord, origin_of
from ..findings import Finding
from .base import DetectionContext

CARD_PATTERN = re.compile(
    r"card|cc[-_]?(num|number|exp|csc|cvv|cvc|name)|\bcvv|\bcvc|\bcsc|\bpan\b|expir|exp[-_]?date"
    r"|security[-_ ]?code",
    re.IGNORECASE,
)


def is_card_like(field: FormInput) -> bool:
    if (field.autocomplete or "").strip().lower().startswith("cc-"):
        return True
    return any(CARD_PATTERN.search(v) for v in (field.name, field.id) if v)


def _keyed(items: Iterable[Any], key: str = "key") -> dict[str, Any]:
    """Index by ``.key``, disambiguating duplicates by order of appearance."""
    out: dict[str, Any] = {}
    counts: dict[str, int] = {}
    for item in items:
        base = getattr(item, key)
        n = counts.get(base, 0)
        counts[base] = n + 1
        out[base if n == 0 else f"{base}[{n}]"] = item
    return out


def _overlaps(box: Box | None, region: Box | None) -> bool:
    return box is not None and region is not None and box.intersects(region)


class FormsDetector:
    name = "forms"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        region = ctx.current.payment_region.box if ctx.current.payment_region else None
        page = ctx.page_origin
        findings = self._forms(ctx, page, region)
        findings += self._iframes(ctx, page, region)
        return findings

    def _action_origin(self, form: FormRecord, page: str | None) -> str | None:
        return origin_of(form.action) if form.action else page

    def _forms(self, ctx: DetectionContext, page: str | None, region: Box | None) -> list[Finding]:
        before: dict[str, FormRecord] = _keyed(ctx.baseline.forms)
        after: dict[str, FormRecord] = _keyed(ctx.current.forms)
        findings: list[Finding] = []
        for key, form in after.items():
            card_fields = [i for i in form.inputs if is_card_like(i)]
            old = before.get(key)
            if old is None:
                action_origin = self._action_origin(form, page)
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="form_added",
                        subject=key,
                        title=f"New form with {len(form.inputs)} field(s)"
                        + (f", {len(card_fields)} card-like" if card_fields else ""),
                        attributes={
                            "card_like": bool(card_fields),
                            "card_fields": len(card_fields),
                            "cross_origin_action": action_origin not in (None, page),
                            "overlaps_payment_region": _overlaps(form.box, region),
                            "orphan_inputs": form.orphan,
                        },
                        evidence={
                            "action": form.action,
                            "method": form.method,
                            "inputs": [i.key for i in form.inputs],
                            "frame_url": form.frame_url,
                        },
                    )
                )
                continue
            old_origin, new_origin = self._action_origin(old, page), self._action_origin(form, page)
            if old_origin != new_origin:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="action_changed",
                        subject=key,
                        title=f"Form now submits to {new_origin} (was {old_origin})",
                        attributes={
                            "cross_origin": new_origin != page,
                            "card_like": bool(card_fields),
                        },
                        evidence={"before": old.action, "after": form.action},
                    )
                )
            elif (old.action or "") != (form.action or ""):
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="action_path_changed",
                        subject=key,
                        title="Form action path changed on the same origin",
                        attributes={"card_like": bool(card_fields)},
                        evidence={"before": old.action, "after": form.action},
                    )
                )
            if old.method != form.method:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="method_changed",
                        subject=key,
                        title=f"Form method changed from {old.method} to {form.method}",
                        attributes={"card_like": bool(card_fields)},
                        evidence={"before": old.method, "after": form.method},
                    )
                )
            old_inputs = _keyed(old.inputs)
            for input_key, field in _keyed(form.inputs).items():
                if input_key not in old_inputs:
                    findings.append(
                        Finding(
                            detector=self.name,
                            change_type="input_added",
                            subject=f"{key}/{input_key}",
                            title=f"New form field {input_key}",
                            attributes={
                                "card_like": is_card_like(field),
                                "hidden": field.type == "hidden",
                            },
                            evidence={
                                "name": field.name,
                                "type": field.type,
                                "autocomplete": field.autocomplete,
                            },
                        )
                    )
        for key, form in before.items():
            if key not in after:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="form_removed",
                        subject=key,
                        title="Form no longer present",
                        attributes={"card_like": any(is_card_like(i) for i in form.inputs)},
                        evidence={"action": form.action},
                    )
                )
        return findings

    def _iframes(
        self, ctx: DetectionContext, page: str | None, region: Box | None
    ) -> list[Finding]:
        before: dict[str, IframeRecord] = _keyed(ctx.baseline.iframes)
        after: dict[str, IframeRecord] = _keyed(ctx.current.iframes)
        findings: list[Finding] = []
        for key, frame in after.items():
            if key in before:
                continue
            origin = origin_of(frame.src)
            findings.append(
                Finding(
                    detector=self.name,
                    change_type="iframe_added",
                    subject=key,
                    title=f"New {'hidden ' if not frame.visible else ''}iframe: {frame.src}",
                    attributes={
                        "hidden": not frame.visible,
                        "offscreen": frame.offscreen,
                        "cross_origin": origin is not None and origin != page,
                        "overlaps_payment_region": frame.visible and _overlaps(frame.box, region),
                    },
                    evidence={
                        "src": frame.src,
                        "box": None
                        if frame.box is None
                        else [frame.box.x, frame.box.y, frame.box.width, frame.box.height],
                        "sandbox": frame.sandbox,
                    },
                )
            )
        for key, frame in before.items():
            if key not in after:
                findings.append(
                    Finding(
                        detector=self.name,
                        change_type="iframe_removed",
                        subject=key,
                        title=f"Iframe no longer present: {frame.src}",
                    )
                )
        return findings
