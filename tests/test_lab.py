"""Lab shop behaviour and the section 5 safety rules, without a browser."""

import re
from importlib.resources import files

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from blink_visual.errors import BlinkError
from blink_visual.lab import SCENARIOS, lab_target
from blink_visual.lab.app import LabState, build_cdn, build_shop, build_sink, sri
from blink_visual.lab.server import Lab

ASSETS = files("blink_visual.lab") / "assets"


@pytest.fixture
def state():
    return LabState("http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3")


@pytest.fixture
def shop(state):
    return TestClient(build_shop(state))


def checkout(shop, state, scenario):
    state.set_scenario(scenario)
    return shop.get("/checkout")


def test_clean_checkout_has_security_headers_and_test_placeholders(shop, state):
    response = checkout(shop, state, "clean")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "script-src 'self' http://127.0.0.1:2 'sha256-" in csp
    assert "'unsafe-inline'" not in csp
    for header in ("strict-transport-security", "x-frame-options", "x-content-type-options"):
        assert header in response.headers
    html = response.text
    assert "4242 4242 4242 4242" in html
    assert 'action="/pay"' in html
    assert f'integrity="{sri(ASSETS.joinpath("widget.js").read_text("utf-8"))}"' in html


def test_noise_rotates_but_structure_does_not(shop, state):
    a, b = checkout(shop, state, "clean").text, checkout(shop, state, "clean").text
    assert a != b
    token = re.compile(r'(content|value)="[0-9a-f]{32}"')
    strip = re.compile(r"Rendered [^<]+|data-render-id=\"\w+\"|<div class=\"promo\">[^<]+")
    assert strip.sub("", token.sub("", a)) == strip.sub("", token.sub("", b))


@pytest.mark.parametrize(
    ("scenario", "needle"),
    [
        ("new_third_party_script", "/lib/analytics.js"),
        ("inline_script_injected", "__blinkLabInjected"),
        ("form_action_changed", 'action="http://127.0.0.1:3/pay"'),
        ("hidden_iframe_added", 'src="http://127.0.0.1:3/frame"'),
        ("overlay_form_added", "lab-overlay"),
        ("visual_payment_area_changed", "style_changed.css"),
    ],
)
def test_html_scenarios(shop, state, scenario, needle):
    assert needle not in checkout(shop, state, "clean").text
    assert needle in checkout(shop, state, scenario).text


def test_header_scenarios(shop, state):
    assert "content-security-policy" not in checkout(shop, state, "csp_removed").headers
    weakened = checkout(shop, state, "csp_weakened_unsafe_inline")
    assert "'unsafe-inline'" in weakened.headers["content-security-policy"]


def test_script_and_config_scenarios(shop, state):
    state.set_scenario("clean")
    clean_js = shop.get("/static/app.js").text
    assert "beacon_url" not in shop.get("/api/config").json()
    state.set_scenario("modified_approved_script")
    assert shop.get("/static/app.js").text != clean_js
    state.set_scenario("new_beacon_destination")
    assert shop.get("/api/config").json()["beacon_url"] == "http://127.0.0.1:3/collect"


def test_admin_endpoint_switches_scenarios(shop, state):
    assert shop.get("/__admin/scenario").json()["scenario"] == "clean"
    assert shop.post("/__admin/scenario?scenario=csp_removed").json()["scenario"] == "csp_removed"
    assert state.scenario == "csp_removed"
    assert shop.post("/__admin/scenario?scenario=nope").status_code == 400
    assert shop.get("/healthz").json()["status"] == "ok"
    assert shop.post("/pay", data={"cardnumber": "4242"}).status_code == 200


def test_cdn_and_sink(state):
    cdn = TestClient(build_cdn(state))
    widget = cdn.get("/lib/widget.js")
    assert widget.headers["access-control-allow-origin"] == "*"
    assert cdn.get("/lib/analytics.js").status_code == 200
    sink = TestClient(build_sink(state))
    assert sink.post("/collect", content=b'{"ping":1}').status_code == 204
    assert sink.get("/frame").status_code == 200
    assert sink.post("/pay").status_code == 200


def test_every_scenario_renders(shop, state):
    for name in SCENARIOS:
        assert checkout(shop, state, name).status_code == 200


def test_lab_refuses_non_loopback_and_unknown_scenarios():
    with pytest.raises(BlinkError, match="loopback"):
        Lab(host="0.0.0.0")
    with pytest.raises(BlinkError, match="unknown scenario"):
        Lab(scenario="nope")


def test_lab_target_matches_lab_noise():
    target = lab_target("http://127.0.0.1:8780/checkout")
    assert target["masks"] == [".timestamp", ".promo"]
    assert target["payment_region"] == "#payment"


# --- BUILD_PLAN.md section 5: fixtures must never be functional skimmers ---------------

FORBIDDEN_JS = [
    r"\.value\b",
    r"FormData",
    r"querySelector[^;]*input",
    r"addEventListener\(\s*['\"](input|change|keydown|keyup|keypress|submit)",
    r"XMLHttpRequest",
    r"WebSocket",
    r"new\s+Image",
    r"\beval\b",
    r"document\.cookie",
    r"localStorage",
]


@pytest.mark.parametrize("name", ["app.js", "app_modified.js", "widget.js", "analytics.js"])
def test_lab_scripts_are_not_skimmers(name):
    source = ASSETS.joinpath(name).read_text("utf-8")
    for pattern in FORBIDDEN_JS:
        assert not re.search(pattern, source), f"{name} matches forbidden pattern {pattern}"
    for beacon in re.findall(r"sendBeacon\(([^)]*)\)", source):
        assert beacon.endswith("'{\"ping\":1}'"), "beacons must send only the constant payload"


def test_lab_html_uses_only_published_test_card_numbers(shop, state):
    for name in SCENARIOS:
        html = checkout(shop, state, name).text
        for digits in re.findall(r"\b(?:\d[ -]?){13,19}\b", html):
            assert re.sub(r"\D", "", digits) == "4242424242424242"


def test_shop_flow_needs_cart_and_details(shop, state):
    empty = shop.get("/shop/checkout", follow_redirects=False)
    assert (empty.status_code, empty.headers["location"]) == (302, "/shop/cart?empty=1")
    assert "Your cart is empty" in shop.get("/shop/cart").text
    assert shop.get("/shop/details", follow_redirects=False).status_code == 303
    added = shop.post("/shop/cart/add", follow_redirects=False)
    assert added.status_code == 303 and "lab_cart" in added.cookies
    assert 'id="cart-items"' in shop.get("/shop/cart").text
    assert shop.get("/shop/checkout", follow_redirects=False).headers["location"] == "/shop/details"
    # The details step is recorded without reading the body; then payment is reachable.
    done = shop.post("/shop/details", data={"email": "x@example.com"}, follow_redirects=False)
    assert done.headers["location"] == "/shop/checkout"
    payment = shop.get("/shop/checkout")
    assert payment.status_code == 200 and 'id="checkout-form"' in payment.text
    assert all(set(flags) == {"items", "details"} for flags in state.carts.values())


def test_shop_pages_have_no_scripts(shop):
    for path in ("/shop", "/shop/cart"):
        assert "<script" not in shop.get(path).text


def test_staging_checkout_requires_auth(shop):
    import base64

    assert shop.get("/staging/checkout").status_code == 401
    basic = base64.b64encode(b"lab:lab-staging-pass").decode()
    assert (
        shop.get("/staging/checkout", headers={"Authorization": f"Basic {basic}"}).status_code
        == 200
    )
    assert (
        shop.get("/staging/checkout", headers={"X-Lab-Token": "lab-staging-token"}).status_code
        == 200
    )
    assert shop.get("/staging/checkout", headers={"X-Lab-Token": "wrong"}).status_code == 401


def test_cdn_and_sink_record_leaked_auth_header_names(state):
    cdn = TestClient(build_cdn(state))
    cdn.get("/lib/widget.js", headers={"X-Lab-Token": "secret-value"})
    assert state.leaked_auth == [f"{state.cdn_origin}/lib/widget.js x-lab-token"]
