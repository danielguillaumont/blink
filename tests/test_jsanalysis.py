"""Static JS risk heuristics.

Fixtures are short, NON-FUNCTIONAL snippets that merely contain the syntactic patterns a
heuristic looks for (BUILD_PLAN.md section 5). None of them read data from a real form and
sends it anywhere: values are never passed to the network calls, which target placeholders.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from blink_visual.jsanalysis import analyze, entropy

CORPUS = Path(__file__).parent / ".cache" / "js-corpus"


def factors(source: str) -> set[str]:
    return {f.name for f in analyze(source).factors}


POSITIVE = {
    "dynamic_code": [
        'eval("1 + 1");',
        'var f = new Function("return 1");',
        'setTimeout("noop()", 10);',
        'window["eval"]("0");',
    ],
    "decode_chain": [
        'var s = atob("aGVsbG8=");',
        "var t = String.fromCharCode(104, 105, 33);",
        "var u = String.fromCharCode(...codes);",
        'var v = decodeURIComponent(escape("x"));',
    ],
    "high_entropy_strings": ['var k = "Zx9Qp2Lm7Vb4Nc8Rt1Yw6Ks3Hd5Gf0JaUe-TqXoBiPlMn";'],
    "dynamic_script_element": ['var el = document.createElement("script");'],
    "payment_field_listeners": [
        'function w(){ document.getElementById("cc-number").addEventListener("input", function(){}); }'
    ],
    "read_and_send": [
        # Co-occurrence only: the value is never passed to the request.
        'function p(el){ var n = el.value.length; fetch("about:blank"); return n; }',
        'function q(form){ var d = new FormData(form); navigator.sendBeacon("about:blank", "{}"); return d; }',
        "function r(el){ var n = el.value; var x = new XMLHttpRequest(); return [n, x]; }",
        "function s(el){ var n = el.value; var i = new Image(); return [n, i]; }",
        'function t(el){ var n = el.value; var x; x.open("POST", "about:blank"); return n; }',
    ],
    "payment_field_references": ['var label = "Card number";', "var f = 'cvv';"],
    "obfuscator_identifiers": [
        "var _0x1a2b = 1, _0x3c4d = 2, _0x5e6f = 3, _0x7a8b = 4, _0x9c0d = 5;"
    ],
    "string_array_rotation": [
        'var a = ["a","b","c","d","e","f","g","h","i","j"]; a.push(a.shift());',
        'var a = ["a","b","c","d","e","f","g","h","i","j"]; a["push"](a["shift"]());',
    ],
}

NEGATIVE = {
    "dynamic_code": ["setTimeout(function(){}, 10);", "var evaluate = 1; evaluate++;"],
    "decode_chain": [
        "String.fromCharCode(n + 65536);",
        "String.fromCharCode(event.which);",
        "decodeURIComponent(location.hash);",
    ],
    "high_entropy_strings": [
        'var msg = "This is a long but perfectly ordinary English sentence in a library.";'
    ],
    "dynamic_script_element": ['document.createElement("div");', "document.createElement(tag);"],
    "payment_field_listeners": [
        'el.addEventListener("click", function(){});',
        'function w(){ document.getElementById("search").addEventListener("input", function(){}); }',
    ],
    "read_and_send": [
        # Read and send in *different* functions (a library in one big IIFE).
        "(function(){ function a(el){ return el.value; } function b(){ fetch('about:blank'); } })();",
        'function c(){ fetch("about:blank"); }',
        "function x(el){ return el.value; }",
        'function o(){ var x; x.open("GET", "about:blank"); var v = el.value; }',
    ],
    "obfuscator_identifiers": ["var _0x1 = 1, a = 2;"],
    "string_array_rotation": [
        "queue.push(item); queue.shift();",
        'var a = ["a"]; a.push(a.shift());',
    ],
}


@pytest.mark.parametrize(
    ("factor", "source"), [(k, s) for k, items in POSITIVE.items() for s in items]
)
def test_positive_snippets(factor, source):
    assert factor in factors(source), analyze(source).to_dict()


@pytest.mark.parametrize(
    ("factor", "source"), [(k, s) for k, items in NEGATIVE.items() for s in items]
)
def test_negative_snippets(factor, source):
    assert factor not in factors(source), analyze(source).to_dict()


def test_combined_patterns_score_high_and_are_explained():
    source = (
        "var _0xa1=1,_0xb2=2,_0xc3=3,_0xd4=4,_0xe5=5;"
        'function z(el){ var n = el.value; navigator.sendBeacon("about:blank", "{}"); return n; }'
        'eval(atob("MA=="));'
    )
    report = analyze(source)
    assert report.score >= 70
    names = [f.name for f in report.factors]
    assert names[0] == "read_and_send"  # sorted by weight
    assert all(f.explanation for f in report.factors)
    assert report.factors[0].examples
    assert report.to_dict()["score"] == report.score


def test_score_is_capped_and_empty_source_is_zero():
    everything = " ".join(s for items in POSITIVE.values() for s in items)
    assert analyze(everything).score == 100
    assert analyze("").score == 0
    assert analyze(b"\xff\xfe not utf-8").parsed


def test_oversized_source_is_not_parsed():
    report = analyze(b"x" * (3 * 1024 * 1024 + 1))
    assert not report.parsed
    assert report.score == 0
    assert "larger than" in (report.error or "")


def test_entropy():
    assert entropy("") == 0
    assert entropy("aaaa") == 0
    assert entropy("ab") == pytest.approx(1.0)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=2000))
def test_parser_never_crashes_on_text(source):
    report = analyze(source)
    assert 0 <= report.score <= 100


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=2000))
def test_parser_never_crashes_on_bytes(source):
    report = analyze(source)
    assert 0 <= report.score <= 100


JS_TOKENS = st.sampled_from(
    [
        "eval(",
        "new Function(",
        "atob(",
        ")",
        "(",
        "{",
        "}",
        ";",
        ".value",
        "fetch(",
        '"script"',
        "document.createElement(",
        "addEventListener(",
        '"input"',
        "function f(",
        "=>",
        "_0xabc",
        "[",
        "]",
        ",",
        "'cc-number'",
        "push(",
        "shift()",
        "`",
        "${",
        "/*",
    ]
)


@settings(max_examples=300, deadline=None)
@given(st.lists(JS_TOKENS, max_size=200).map("".join))
def test_parser_never_crashes_on_js_like_soup(source):
    report = analyze(source)
    assert 0 <= report.score <= 100


@pytest.mark.parametrize(
    "name", ["jquery.min.js", "react.production.min.js", "react-dom.production.min.js"]
)
def test_real_minified_libraries_score_low(name):
    path = CORPUS / name
    if not path.exists():
        pytest.skip("JS corpus not fetched; run `python scripts/fetch_js_corpus.py` (needs npm)")
    report = analyze(path.read_bytes())
    assert report.parsed
    assert report.score < 30, report.to_dict()


def test_lab_scripts_score_zero():
    from importlib.resources import files

    assets = files("blink_visual.lab") / "assets"
    for name in ("app.js", "app_modified.js", "widget.js", "analytics.js"):
        assert analyze(assets.joinpath(name).read_text("utf-8")).score == 0
