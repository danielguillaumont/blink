import pytest

from blink_visual.capture.normalize import VOLATILE, dom_hash, extract_region, normalize_dom
from blink_visual.config import NormalizeConfig
from blink_visual.errors import ConfigError

PAGE = """<!doctype html><html><head>
<meta name="csrf-token" content="{token}">
<script nonce="{nonce}">window.x = 1;</script></head>
<body data-render-id="{rid}">
<span class="ts">Rendered {ts}</span><div class="promo"><b>{promo}</b> today</div>
<div id="chat">chat widget {rid}</div>
<section id="payment"><form action="/pay"><input name="csrf" value="{token}">
<input name="cardnumber"></form></section>
<p>build {build}</p></body></html>"""

CONFIG = NormalizeConfig(
    volatile_attributes=[
        {"selector": 'meta[name="csrf-token"]', "attributes": ["content"]},
        {"selector": 'input[name="csrf"]', "attributes": ["value"]},
        {"selector": "body", "attributes": ["data-render-id", "missing-attr"]},
    ],
    volatile_text=[".ts", ".promo"],
    remove=["#chat"],
    regexes=[{"pattern": r"build [0-9a-f]{8}", "replacement": "build <id>"}],
)


def page(**values):
    defaults = {
        "token": "aaaa",
        "nonce": "n1",
        "rid": "r1",
        "ts": "2026-01-01T00:00:00",
        "promo": "Sale",
        "build": "deadbeef",
    }
    defaults.update(values)
    return PAGE.format(**defaults)


def test_volatile_values_do_not_change_the_hash():
    a = normalize_dom(page(), CONFIG)
    b = normalize_dom(
        page(
            token="bbbb",
            nonce="n2",
            rid="r2",
            ts="2027-02-02T11:11:11",
            promo="Other promo",
            build="0badf00d",
        ),
        CONFIG,
    )
    assert a == b
    assert dom_hash(a) == dom_hash(b)
    assert "aaaa" not in a
    assert "nonce" not in a
    assert "chat widget" not in a
    assert "build <id>" in a
    assert f'content="{VOLATILE}"' in a


def test_structure_is_preserved():
    normalized = normalize_dom(page(), CONFIG)
    assert '<div class="promo">[volatile]<b></b>' in normalized
    assert "data-render-id" in normalized
    assert 'name="cardnumber"' in normalized


def test_structural_change_changes_the_hash():
    base = dom_hash(normalize_dom(page(), CONFIG))
    tampered = page().replace('<input name="cardnumber">', '<input name="cardnumber"><input>')
    assert dom_hash(normalize_dom(tampered, CONFIG)) != base
    moved = page().replace('action="/pay"', 'action="https://evil.example/pay"')
    assert dom_hash(normalize_dom(moved, CONFIG)) != base


def test_default_config_only_strips_nonce():
    html = '<script nonce="abc">1</script><p data-x="1">t</p>'
    assert normalize_dom(html, NormalizeConfig()) == '<script>1</script><p data-x="1">t</p>'


def test_invalid_selector_is_a_config_error():
    with pytest.raises(ConfigError, match="invalid CSS selector"):
        normalize_dom("<p></p>", NormalizeConfig(remove=["p[["]))


def test_extract_region():
    normalized = normalize_dom(page(), CONFIG)
    region = extract_region(normalized, "#payment")
    assert region is not None
    assert region.startswith('<section id="payment">')
    assert extract_region(normalized, "#nope") is None
