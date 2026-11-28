"""Static JavaScript risk heuristics (tree-sitter-javascript).

The analyzer never executes code. It walks the syntax tree once and looks for patterns
common in e-skimmers and rare in ordinary libraries. Each heuristic contributes a weighted
factor with a plain-English explanation; the score is their sum, capped at 100.

"Same function" checks use the innermost enclosing function only (nested functions are
separate scopes), so a library wrapped in one big IIFE is not penalized for having a
network call in one function and a ``.value`` read in another.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node, Parser

MAX_SOURCE_BYTES = 3 * 1024 * 1024
MAX_EXAMPLES = 3

FUNCTION_NODES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)
LISTENED_EVENTS = frozenset({"input", "change", "keydown", "keyup", "keypress", "blur", "paste"})
SEND_CALLS = frozenset({"fetch", "sendBeacon"})
SEND_CONSTRUCTORS = frozenset({"XMLHttpRequest", "WebSocket", "Image", "EventSource"})
DECODE_CALLS = frozenset({"atob", "fromCharCode", "unescape", "decodeURIComponent"})
TIMER_CALLS = frozenset({"setTimeout", "setInterval"})
PAYMENT_TEXT = re.compile(
    r"cc-(number|csc|exp)|card.?(number|num|holder)|cardnumber|\bcvv\b|\bcvc\b|\bcsc\b"
    r"|security.?code|exp.?date|\bpan\b",
    re.IGNORECASE,
)
HEX_IDENTIFIER = re.compile(r"^_0x[0-9a-f]{3,}$")


@dataclass(frozen=True)
class Factor:
    name: str
    weight: int
    explanation: str
    count: int = 1
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskReport:
    score: int
    factors: tuple[Factor, ...]
    parsed: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "parsed": self.parsed,
            "error": self.error,
            "factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "count": f.count,
                    "explanation": f.explanation,
                    "examples": list(f.examples),
                }
                for f in self.factors
            ],
        }


@dataclass
class _Scope:
    value_reads: list[str] = field(default_factory=list)
    form_data: list[str] = field(default_factory=list)
    sends: list[str] = field(default_factory=list)
    listeners: list[str] = field(default_factory=list)
    payment_text: list[str] = field(default_factory=list)


@cache
def _parser() -> Parser:
    import tree_sitter_javascript
    from tree_sitter import Language, Parser

    return Parser(Language(tree_sitter_javascript.language()))


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


def _where(node: Node) -> str:
    row, column = node.start_point
    snippet = " ".join(_text(node).split())[:80]
    return f"{row + 1}:{column + 1} {snippet}"


def _string_value(node: Node) -> str | None:
    if node.type == "string":
        return _text(node)[1:-1]
    if node.type == "template_string" and not any(
        c.type == "template_substitution" for c in node.children
    ):
        return _text(node)[1:-1]
    return None


def _callee_name(node: Node) -> str | None:
    """``eval`` for ``eval(x)``; ``fromCharCode`` for ``String.fromCharCode(x)``."""
    target = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    if target is None:
        return None
    if target.type == "identifier":
        return _text(target)
    if target.type == "member_expression":
        prop = target.child_by_field_name("property")
        return _text(prop) if prop is not None else None
    if target.type == "subscript_expression":
        index = target.child_by_field_name("index")
        return _string_value(index) if index is not None else None
    return None


def _first_argument(node: Node) -> Node | None:
    args = node.child_by_field_name("arguments")
    if args is None:
        return None
    named = [c for c in args.named_children if c.type != "comment"]
    return named[0] if named else None


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _is_high_entropy(value: str) -> bool:
    return len(value) >= 40 and " " not in value and entropy(value) >= 4.8


class _Collector:
    def __init__(self) -> None:
        self.scopes: list[_Scope] = [_Scope()]
        self.dynamic_code: list[str] = []
        self.decode_calls: list[str] = []
        self.script_elements: list[str] = []
        self.high_entropy: list[str] = []
        self.hex_identifiers: set[str] = set()
        self.rotations: list[str] = []
        self.largest_string_array = 0

    def visit(self, node: Node, scope: _Scope) -> None:
        kind = node.type
        if kind in ("call_expression", "new_expression"):
            self._call(node, scope, constructor=kind == "new_expression")
        elif kind == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is not None and _text(prop) == "value":
                scope.value_reads.append(_where(node))
        elif kind == "identifier":
            name = _text(node)
            if HEX_IDENTIFIER.match(name):
                self.hex_identifiers.add(name)
        elif kind == "array":
            strings = sum(1 for c in node.named_children if c.type == "string")
            self.largest_string_array = max(self.largest_string_array, strings)
        value = _string_value(node) if kind in ("string", "template_string") else None
        if value is not None:
            if PAYMENT_TEXT.search(value):
                scope.payment_text.append(_where(node))
            if _is_high_entropy(value):
                self.high_entropy.append(f"{node.start_point[0] + 1}: {value[:24]}…")

    def _call(self, node: Node, scope: _Scope, *, constructor: bool) -> None:
        name = _callee_name(node)
        if name is None:
            return
        first = _first_argument(node)
        first_text = _string_value(first) if first is not None else None
        if constructor:
            if name == "Function":
                self.dynamic_code.append(_where(node))
            elif name == "FormData":
                scope.form_data.append(_where(node))
            elif name in SEND_CONSTRUCTORS:
                scope.sends.append(_where(node))
            return
        if name == "eval" or (
            name in TIMER_CALLS
            and first is not None
            and first.type in ("string", "template_string")
        ):
            self.dynamic_code.append(_where(node))
        elif name in DECODE_CALLS:
            if self._is_decode(name, node):
                self.decode_calls.append(_where(node))
        elif name in SEND_CALLS or (name == "open" and self._is_xhr_open(node)):
            scope.sends.append(_where(node))
        elif name == "createElement" and (first_text or "").lower() == "script":
            self.script_elements.append(_where(node))
        elif name == "addEventListener" and (first_text or "").lower() in LISTENED_EVENTS:
            scope.listeners.append(_where(node))
        elif name == "push":
            argument = _first_argument(node)
            if (
                argument is not None
                and argument.type == "call_expression"
                and _callee_name(argument) == "shift"
            ):
                self.rotations.append(_where(node))

    @staticmethod
    def _is_decode(name: str, node: Node) -> bool:
        """Payload decoding, not ordinary Unicode or URL handling.

        ``atob``/``unescape`` always count. ``String.fromCharCode`` counts for literal
        code-point sequences (3+ numbers) or spreads; libraries call it with arithmetic
        such as ``fromCharCode(n + 65536)``. ``decodeURIComponent`` counts only when it
        wraps another decoder (``decodeURIComponent(escape(atob(x)))``).
        """
        if name in ("atob", "unescape"):
            return True
        args = node.child_by_field_name("arguments")
        named = [] if args is None else [c for c in args.named_children if c.type != "comment"]
        if name == "fromCharCode":
            numbers = sum(1 for c in named if c.type == "number")
            return numbers >= 3 or any(c.type == "spread_element" for c in named)
        if name == "decodeURIComponent" and named and named[0].type == "call_expression":
            return _callee_name(named[0]) in {"escape", "atob", "unescape"}
        return False

    @staticmethod
    def _is_xhr_open(node: Node) -> bool:
        args = node.child_by_field_name("arguments")
        if args is None:
            return False
        first = next((c for c in args.named_children if c.type != "comment"), None)
        value = _string_value(first) if first is not None else None
        return (value or "").upper() in {"POST", "PUT"}


def _walk(root: Node, collector: _Collector) -> None:
    stack: list[tuple[Node, _Scope]] = [(root, collector.scopes[0])]
    while stack:
        node, scope = stack.pop()
        if node.type in FUNCTION_NODES:
            scope = _Scope()
            collector.scopes.append(scope)
        collector.visit(node, scope)
        stack.extend((child, scope) for child in reversed(node.children))


def _examples(items: list[str]) -> tuple[str, ...]:
    return tuple(items[:MAX_EXAMPLES])


def analyze(source: str | bytes) -> RiskReport:
    """Score ``source`` from 0 (no skimmer-like patterns) to 100. Never raises on bad input."""
    data = source.encode("utf-8", errors="replace") if isinstance(source, str) else source
    if len(data) > MAX_SOURCE_BYTES:
        return RiskReport(0, (), parsed=False, error=f"larger than {MAX_SOURCE_BYTES} bytes")
    try:
        tree = _parser().parse(data)
    except Exception as exc:  # parsers must never crash a scan
        return RiskReport(0, (), parsed=False, error=f"{type(exc).__name__}: {exc}")
    collector = _Collector()
    _walk(tree.root_node, collector)
    return _score(collector)


def _score(c: _Collector) -> RiskReport:
    factors: list[Factor] = []
    if c.dynamic_code:
        factors.append(
            Factor(
                "dynamic_code",
                25,
                "Executes strings as code (eval, new Function or a string timer), which hides "
                "behaviour from review and from static allowlists.",
                len(c.dynamic_code),
                _examples(c.dynamic_code),
            )
        )
    if c.decode_calls:
        chained = len(c.decode_calls) >= 2 or bool(c.dynamic_code)
        factors.append(
            Factor(
                "decode_chain",
                15 if chained else 5,
                "Decodes data at runtime (atob, String.fromCharCode, unescape); skimmers decode "
                "hidden URLs and payloads this way.",
                len(c.decode_calls),
                _examples(c.decode_calls),
            )
        )
    if c.high_entropy:
        factors.append(
            Factor(
                "high_entropy_strings",
                min(15, 5 * len(c.high_entropy)),
                "Contains long random-looking string literals, typical of encoded or encrypted "
                "payloads.",
                len(c.high_entropy),
                _examples(c.high_entropy),
            )
        )
    if c.script_elements:
        factors.append(
            Factor(
                "dynamic_script_element",
                15,
                "Creates <script> elements at runtime, which loads further code that never "
                "appears in the page source.",
                len(c.script_elements),
                _examples(c.script_elements),
            )
        )
    listen = [s for s in c.scopes if s.listeners and s.payment_text]
    if listen:
        factors.append(
            Factor(
                "payment_field_listeners",
                20,
                "Listens to input/change/key events in the same function that references "
                "payment field names.",
                sum(len(s.listeners) for s in listen),
                _examples([x for s in listen for x in s.listeners]),
            )
        )
    exfil = [s for s in c.scopes if (s.value_reads or s.form_data) and s.sends]
    if exfil:
        factors.append(
            Factor(
                "read_and_send",
                35,
                "Reads form field values or FormData and sends a network request (fetch, "
                "sendBeacon, XMLHttpRequest, WebSocket or an image) in the same function. This "
                "is the core of a skimmer.",
                len(exfil),
                _examples([x for s in exfil for x in (*s.form_data, *s.value_reads, *s.sends)]),
            )
        )
    payment = [x for s in c.scopes for x in s.payment_text]
    if payment and not listen:
        factors.append(
            Factor(
                "payment_field_references",
                10,
                "References payment field names (card number, CVV, expiry).",
                len(payment),
                _examples(payment),
            )
        )
    if len(c.hex_identifiers) >= 5:
        factors.append(
            Factor(
                "obfuscator_identifiers",
                20,
                "Uses many hex-named identifiers (_0x…), the signature of common JavaScript "
                "obfuscators.",
                len(c.hex_identifiers),
                tuple(sorted(c.hex_identifiers)[:MAX_EXAMPLES]),
            )
        )
    if c.rotations and c.largest_string_array >= 10:
        factors.append(
            Factor(
                "string_array_rotation",
                20,
                "Rotates a large string array (push(shift())), an obfuscator technique that hides "
                "strings such as URLs.",
                len(c.rotations),
                _examples(c.rotations),
            )
        )
    score = min(100, sum(f.weight for f in factors))
    return RiskReport(score, tuple(sorted(factors, key=lambda f: -f.weight)))


__all__ = ["Factor", "RiskReport", "analyze", "entropy"]
