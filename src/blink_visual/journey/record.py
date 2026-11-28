"""``blink record``: draft a journey from a Playwright codegen session.

Playwright's recorder writes Python. This module converts the common calls into journey steps
and leaves a ``# TODO`` comment for anything it doesn't understand. Typed values that look
like a card number or an e-mail address become ``{{canary.pan}}`` / ``{{faker.email}}``; other
typed values are kept for review. Clicks that look like placing the order are dropped.
"""

from __future__ import annotations

import ast
import re
from typing import Any

import yaml

from .model import ORDER_LIKE

CARD_LIKE = re.compile(r"^[\d\s-]{12,23}$")
EMAIL_LIKE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _literal(node: ast.expr) -> Any:
    try:
        return ast.literal_eval(node)
    except ValueError:
        return None


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _selector(call: ast.Call) -> str | None:
    """A Playwright selector string for a ``page.get_by_*`` / ``page.locator`` call."""
    if not isinstance(call.func, ast.Attribute):
        return None
    name = call.func.attr
    args = [_literal(a) for a in call.args]
    kwargs = {k.arg: _literal(k.value) for k in call.keywords if k.arg}
    first = args[0] if args else None
    if not isinstance(first, str):
        return None
    if name == "locator":
        return first
    if name == "get_by_role":
        options = f"[name={_quote(kwargs['name'])}]" if isinstance(kwargs.get("name"), str) else ""
        return f"role={first}{options}"
    if name == "get_by_text":
        return f"text={first}"
    if name == "get_by_label":
        return f"internal:label={_quote(first)}i"
    if name == "get_by_placeholder":
        return f"[placeholder={_quote(first)}]"
    if name == "get_by_test_id":
        return f"[data-testid={_quote(first)}]"
    return None


def _chain(node: ast.expr) -> tuple[str | None, str | None]:
    """``(frame selector, element selector)`` for ``page[.frame_locator(f)].<locator call>``."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None, None
    selector = _selector(node)
    if selector is None:
        return None, None
    parent = node.func.value
    while isinstance(parent, ast.Attribute) and parent.attr in {"first", "last"}:
        parent = parent.value
    if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute):
        if parent.func.attr == "frame_locator" and parent.args:
            frame = _literal(parent.args[0])
            return (frame if isinstance(frame, str) else None), selector
        if parent.func.attr in {"first", "nth"}:
            return _chain(parent.func.value)
    if isinstance(parent, ast.Attribute) and parent.attr in {"first", "last"}:
        return _chain(parent.value)
    return None, selector


def _value_template(value: str) -> str:
    if CARD_LIKE.match(value) and sum(c.isdigit() for c in value) >= 12:
        return "{{canary.pan}}"
    if EMAIL_LIKE.match(value):
        return "{{faker.email}}"
    return value


def codegen_to_steps(source: str) -> list[dict[str, Any] | str]:
    """Steps (dicts) and ``# TODO`` comments (strings) from Playwright codegen Python."""
    tree = ast.parse(source)
    out: list[dict[str, Any] | str] = []
    statements = [n for n in ast.walk(tree) if isinstance(n, ast.Expr)]
    for node in sorted(statements, key=lambda n: (n.lineno, n.col_offset)):
        call = node.value
        if not isinstance(call, ast.Call):
            continue
        if not isinstance(call.func, ast.Attribute):
            continue
        method = call.func.attr
        args = [_literal(a) for a in call.args]
        target = call.func.value
        text = ast.unparse(call)
        if method in {"close", "new_page", "new_context", "launch", "stop"}:
            continue
        if method == "goto" and args and isinstance(args[0], str):
            out.append({"goto": args[0]})
            continue
        frame, selector = _chain(target)
        if selector is None:
            out.append(f"# TODO unsupported: {text}")
            continue
        step: dict[str, Any]
        if method in {"click", "dblclick"}:
            step = {"click": selector}
            if ORDER_LIKE.search(selector):
                out.append(
                    f"# REMOVED (looks like placing the order; journeys stop before it): {text}"
                )
                continue
        elif method == "fill" and args and isinstance(args[0], str):
            step = {"fill": {"selector": selector, "value": _value_template(args[0])}}
        elif method == "select_option" and args and isinstance(args[0], str):
            step = {"select": {"selector": selector, "value": args[0]}}
        elif method == "check":
            step = {"check": selector}
        elif method == "press" and args and isinstance(args[0], str):
            step = {"press": {"selector": selector, "key": args[0]}}
        else:
            out.append(f"# TODO unsupported: {text}")
            continue
        if frame:
            step["frame"] = frame
        out.append(step)
    return out


def draft_yaml(name: str, url: str, steps: list[dict[str, Any] | str]) -> str:
    """A ``targets:`` entry to paste into blink.yaml, comments kept in place."""
    lines = [
        "# Drafted by `blink record`: review every selector and value before using it.",
        "targets:",
        f"  - name: {name}",
        f"    url: {url}",
        "    wait_for: null          # set to a selector present on the payment page",
        "    payment_region: null    # set to the payment form container",
        "    journey:",
    ]
    for item in steps:
        if isinstance(item, str):
            lines.append(f"      {item}")
            continue
        dumped = yaml.safe_dump([item], default_flow_style=None, sort_keys=False, width=200)
        for line in dumped.rstrip("\n").splitlines():
            lines.append(f"      {line}")
    lines.append("      - capture: payment")
    return "\n".join(lines) + "\n"
