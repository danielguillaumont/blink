"""Unit tests for each detector on synthetic snapshots (no browser, no network)."""

from __future__ import annotations

import base64
import hashlib
import io
from dataclasses import replace

import numpy as np
import pytest
from helpers import CARD_FORM, HEADERS, NOW, PAGE, context, iframe, script, snapshot
from PIL import Image

from blink_visual.capture.models import (
    Box,
    FormInput,
    FormRecord,
    RegionCapture,
    RequestRecord,
    TlsInfo,
)
from blink_visual.config import TargetConfig
from blink_visual.detect import DETECTORS, run_detectors
from blink_visual.detect.dom import DomDetector, flatten, tree_edit
from blink_visual.detect.forms import FormsDetector, is_card_like
from blink_visual.detect.headers import HeadersDetector
from blink_visual.detect.network import NetworkDetector
from blink_visual.detect.scripts import ScriptsDetector, parse_integrity, sri_matches
from blink_visual.detect.tls import TlsDetector
from blink_visual.detect.visual import VisualDetector
from blink_visual.store import Store


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / ".blink") as opened:
        yield opened


def kinds(findings):
    return {(f.detector, f.change_type) for f in findings}


def by_type(findings, change_type):
    (match,) = [f for f in findings if f.change_type == change_type]
    return match


# --- scripts -----------------------------------------------------------------------


def test_identical_snapshots_produce_no_findings(store):
    base = snapshot()
    assert run_detectors(context(store, base, replace(base, id="snap-2"))) == []


def test_scripts_added_removed_and_changed(store):
    base = snapshot()
    current = snapshot(
        scripts=(
            script("https://shop.example/app.js", "sha384-CHANGED"),
            script("https://evil.example/x.js", "sha384-X"),
            script("https://shop.example/new.js", "sha384-N"),
            script(None, "sha384-INLINE", size=12),
        )
    )
    findings = ScriptsDetector().detect(context(store, base, current))
    third = next(f for f in findings if f.change_type == "added" and "evil" in f.subject)
    first = next(f for f in findings if f.change_type == "added" and "new.js" in f.subject)
    assert third.attributes["cross_origin"] is True
    assert first.attributes["cross_origin"] is False
    changed = by_type(findings, "hash_changed")
    assert changed.evidence["before_sha384"] == "sha384-APP"
    assert changed.evidence["after_sha384"] == "sha384-CHANGED"
    assert by_type(findings, "inline_added").attributes["size"] == 12
    assert by_type(findings, "removed").subject == "https://cdn.example/w.js"
    missing = by_type(findings, "sri_missing")
    assert missing.subject == "https://evil.example/x.js"
    assert missing.attributes["new"] is True


def test_sri_mismatch_with_sha384_and_stored_body(store):
    body = b"console.log('changed')"
    digest = store.put_blob(body, "text/javascript")
    good256 = "sha256-" + base64.b64encode(hashlib.sha256(body).digest()).decode()
    base = snapshot()
    bad = snapshot(
        scripts=(
            script("https://shop.example/app.js", "sha384-APP"),
            script("https://cdn.example/w.js", "sha384-W2", integrity="sha384-W"),
        )
    )
    findings = ScriptsDetector().detect(context(store, base, bad))
    assert by_type(findings, "sri_mismatch").evidence["integrity"] == "sha384-W"
    ok256 = snapshot(
        scripts=(
            script("https://shop.example/app.js", "sha384-APP"),
            script("https://cdn.example/w.js", "sha384-W", integrity=good256, sha256=digest),
        )
    )
    assert "sri_mismatch" not in {
        f.change_type for f in ScriptsDetector().detect(context(store, base, ok256))
    }
    bad256 = replace(
        ok256, scripts=(ok256.scripts[0], replace(ok256.scripts[1], integrity="sha256-x"))
    )
    assert "sri_mismatch" in {
        f.change_type for f in ScriptsDetector().detect(context(store, base, bad256))
    }


def test_integrity_parsing():
    tokens = parse_integrity("sha256-a sha512-b?opt md5-c")
    assert tokens == {"sha256": {"a"}, "sha512": {"b"}}
    body = b"x"
    sha512 = base64.b64encode(hashlib.sha512(body).digest()).decode()
    # Only the strongest algorithm counts: a wrong sha256 does not matter next to a good sha512.
    assert sri_matches(f"sha256-wrong sha512-{sha512}", body) is True
    assert sri_matches("sha512-wrong", body) is False
    assert sri_matches("md5-abc", body) is None


# --- network -----------------------------------------------------------------------


def test_new_destinations(store):
    base = snapshot()
    current = snapshot(
        requests=(
            *base.requests,
            RequestRecord("https://collect.example/c?token=secret", "POST", "ping"),
            RequestRecord("https://fonts.example/f.woff2", "GET", "font"),
            RequestRecord("data:text/plain,hi", "GET", "other"),
        )
    )
    findings = NetworkDetector().detect(context(store, base, current))
    collect = next(f for f in findings if f.subject == "https://collect.example")
    assert collect.attributes == {
        "sends_data": True,
        "websocket": False,
        "beacon": True,
        "request_count": 1,
    }
    assert collect.evidence["urls"] == ["https://collect.example/c"]  # query dropped
    fonts = next(f for f in findings if f.subject == "https://fonts.example")
    assert fonts.attributes["sends_data"] is False
    gone = NetworkDetector().detect(context(store, current, base))
    assert {f.change_type for f in gone} == {"destination_removed"}


# --- headers -----------------------------------------------------------------------


def headers(**changes):
    out = dict(HEADERS)
    for key, value in changes.items():
        name = key.replace("_", "-")
        if value is None:
            out.pop(name, None)
        else:
            out[name] = value
    return out


def detect_headers(store, before, after):
    return HeadersDetector().detect(
        context(store, snapshot(headers=before), snapshot(headers=after))
    )


def test_csp_removed_and_weakened(store):
    removed = detect_headers(store, HEADERS, headers(content_security_policy=None))
    assert kinds(removed) == {("headers", "csp_removed")}
    assert removed[0].attributes["had_script_policy"] is True
    weak = detect_headers(
        store,
        HEADERS,
        headers(
            content_security_policy=HEADERS["content-security-policy"].replace(
                "'self'", "'self' 'unsafe-inline' https:"
            )
        ),
    )
    assert {f.subject for f in weak} == {
        "content-security-policy:unsafe-inline",
        "content-security-policy:wildcard-source",
    }


def test_csp_preexisting_weakness_and_directive_changes(store):
    weak = "script-src 'self' 'unsafe-eval'"
    found = detect_headers(
        store,
        headers(content_security_policy=weak),
        headers(content_security_policy=weak + " https://new.example; img-src 'self'"),
    )
    assert by_type(found, "csp_weakness").attributes == {"weakness": "unsafe-eval"}
    changed = by_type(found, "csp_changed")
    assert changed.attributes["script_sources_added"] == 1
    assert changed.evidence["directives_added"] == ["img-src"]
    gone = detect_headers(
        store,
        headers(content_security_policy="default-src 'self'; script-src 'self'"),
        headers(content_security_policy="default-src 'self'"),
    )
    assert by_type(gone, "csp_changed").attributes["script_directive_removed"] is True


def test_csp_missing_and_added(store):
    none = headers(content_security_policy=None)
    assert kinds(detect_headers(store, none, none)) == {("headers", "csp_missing")}
    added = detect_headers(store, none, HEADERS)
    assert by_type(added, "header_added").subject == "content-security-policy"


@pytest.mark.parametrize(
    ("header", "before", "after", "weakened"),
    [
        ("strict-transport-security", "max-age=31536000; includeSubDomains", "max-age=60", True),
        (
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
            "max-age=31536000",
            True,
        ),
        ("strict-transport-security", "max-age=31536000", "max-age=63072000", False),
        ("x-frame-options", "DENY", "SAMEORIGIN", True),
        ("x-frame-options", "SAMEORIGIN", "DENY", False),
        ("x-content-type-options", "nosniff", "none", True),
        ("referrer-policy", "no-referrer", "unsafe-url", True),
        ("permissions-policy", "payment=(self)", "payment=(*)", True),
    ],
)
def test_header_weakening(store, header, before, after, weakened):
    found = detect_headers(
        store,
        headers(**{header.replace("-", "_"): before}),
        headers(**{header.replace("-", "_"): after}),
    )
    change = by_type(found, "header_changed")
    assert change.attributes["weakened"] is weakened


def test_header_removed_missing_and_framing_coverage(store):
    found = detect_headers(store, HEADERS, headers(x_frame_options=None, referrer_policy=None))
    removed = {f.subject: f for f in found if f.change_type == "header_removed"}
    assert removed["x-frame-options"].attributes["covered_by_csp"] is True
    assert "referrer-policy" in removed
    bare = {"content-security-policy": "script-src 'self'"}
    missing = {
        f.subject for f in detect_headers(store, bare, bare) if f.change_type == "header_missing"
    }
    assert "x-frame-options" in missing
    assert "strict-transport-security" in missing


# --- forms and iframes ---------------------------------------------------------------


def test_form_action_method_and_inputs(store):
    tampered = replace(
        CARD_FORM,
        action="https://evil.example/pay",
        method="get",
        inputs=(*CARD_FORM.inputs, FormInput("cc_exp", "text"), FormInput("tracking", "hidden")),
    )
    found = FormsDetector().detect(context(store, snapshot(), snapshot(forms=(tampered,))))
    assert by_type(found, "action_changed").attributes == {"cross_origin": True, "card_like": True}
    assert by_type(found, "method_changed").evidence == {"before": "post", "after": "get"}
    added = {f.evidence["name"]: f.attributes for f in found if f.change_type == "input_added"}
    assert added["cc_exp"]["card_like"] is True
    assert added["tracking"] == {"card_like": False, "hidden": True}
    path_only = replace(CARD_FORM, action="https://shop.example/pay/v2")
    found = FormsDetector().detect(context(store, snapshot(), snapshot(forms=(path_only,))))
    assert kinds(found) == {("forms", "action_path_changed")}


def test_overlay_form_and_removed_form(store):
    overlay = FormRecord(
        action=PAGE + "#",
        method="get",
        frame_url=PAGE,
        inputs=(FormInput("card_number", "text", "cc-number"),),
        box=Box(400, 150, 380, 200),
    )
    found = FormsDetector().detect(context(store, snapshot(), snapshot(forms=(CARD_FORM, overlay))))
    added = by_type(found, "form_added")
    assert added.attributes["card_like"] is True
    assert added.attributes["overlaps_payment_region"] is True
    removed = FormsDetector().detect(context(store, snapshot(), snapshot(forms=())))
    assert by_type(removed, "form_removed").attributes["card_like"] is True


def test_iframes(store):
    hidden = iframe(
        "https://evil.example/f", visible=False, offscreen=True, box=Box(-9999, 0, 1, 1)
    )
    over = iframe("https://evil.example/o", box=Box(390, 90, 400, 300))
    found = FormsDetector().detect(context(store, snapshot(), snapshot(iframes=(hidden, over))))
    attrs = {f.subject: f.attributes for f in found}
    assert attrs["https://evil.example/f"]["hidden"] is True
    assert attrs["https://evil.example/f"]["overlaps_payment_region"] is False
    assert attrs["https://evil.example/o"]["overlaps_payment_region"] is True
    gone = FormsDetector().detect(context(store, snapshot(iframes=(over,)), snapshot()))
    assert kinds(gone) == {("forms", "iframe_removed")}


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        (FormInput("x", "text", "cc-number"), True),
        (FormInput("card-number", "text"), True),
        (FormInput("security_code", "text"), True),
        (FormInput(None, "text", None, "cvv2"), True),
        (FormInput("email", "email", "email"), False),
        (FormInput("discount", "text"), False),
    ],
)
def test_card_like_fields(field, expected):
    assert is_card_like(field) is expected


# --- dom -----------------------------------------------------------------------------


REGION = (
    '<html><body><section id="payment"><form id="f"><input name="cardnumber">'
    '</form><p class="note">Pay securely</p></section></body></html>'
)


def dom_snapshots(store, before_html, after_html):
    b = store.put_blob(before_html.encode(), "text/html")
    a = store.put_blob(after_html.encode(), "text/html")
    return snapshot(blobs={"dom": b}), snapshot(blobs={"dom": a})


def test_dom_structural_summary(store):
    injected = REGION.replace("</form>", '</form><script>1</script><div class="x"></div>')
    base, current = dom_snapshots(store, REGION, injected)
    (finding,) = DomDetector().detect(context(store, base, current))
    assert finding.attributes["added"] == 2
    assert finding.attributes["sensitive_added"] == 1
    assert "+   script" in finding.evidence["edits"]
    assert store.get_blob(finding.evidence["after_blob"]).decode().count("<script>") == 1


def test_dom_attribute_and_text_changes(store):
    changed = REGION.replace('id="f"', 'id="f" action="x"').replace("Pay securely", "Pay now")
    base, current = dom_snapshots(store, REGION, changed)
    (finding,) = DomDetector().detect(context(store, base, current))
    assert finding.attributes["attributes_changed"] == 1
    assert finding.attributes["text_changed"] == 1
    assert finding.attributes["added"] == 0


def test_dom_region_missing_and_unchanged(store):
    base, current = dom_snapshots(store, REGION, "<html><body><main></main></body></html>")
    assert kinds(DomDetector().detect(context(store, base, current))) == {("dom", "region_missing")}
    base, same = dom_snapshots(store, REGION, REGION)
    assert DomDetector().detect(context(store, base, same)) == []
    no_region = TargetConfig(name="checkout", url=PAGE)
    assert DomDetector().detect(context(store, base, current, no_region)) == []


def test_tree_edit_on_reordered_children():
    before = flatten("<div><a></a><b></b></div>")
    after = flatten("<div><b></b><a></a></div>")
    edit = tree_edit(before, after)
    assert len(edit.added) == len(edit.removed) == 1


# --- visual --------------------------------------------------------------------------


def png(array):
    buffer = io.BytesIO()
    Image.fromarray(array).save(buffer, format="PNG")
    return buffer.getvalue()


def visual_snapshots(store, before, after):
    b = store.put_blob(png(before), "image/png")
    a = store.put_blob(png(after), "image/png")
    return snapshot(blobs={"region_screenshot": b}), snapshot(blobs={"region_screenshot": a})


def test_visual_change_and_evidence(store):
    before = np.full((100, 200, 3), 240, dtype=np.uint8)
    after = before.copy()
    after[20:60, 20:120] = (179, 38, 30)
    base, current = visual_snapshots(store, before, after)
    (finding,) = VisualDetector().detect(context(store, base, current))
    assert finding.attributes["changed_percentage"] == 20.0
    assert finding.attributes["regions"] == 1
    overlay = Image.open(io.BytesIO(store.get_blob(finding.evidence["overlay_blob"])))
    assert overlay.size == (200, 100)
    assert finding.evidence["regions"][0]["width"] == 100


def test_visual_ignores_tiny_noise_and_reports_resizes(store):
    before = np.full((100, 200, 3), 240, dtype=np.uint8)
    noisy = before.copy()
    noisy[5, 5] = 0  # one pixel: below min_region_pixels
    base, current = visual_snapshots(store, before, noisy)
    assert VisualDetector().detect(context(store, base, current)) == []
    taller = np.full((120, 200, 3), 240, dtype=np.uint8)
    base, current = visual_snapshots(store, before, taller)
    (finding,) = VisualDetector().detect(context(store, base, current))
    assert finding.attributes["resized"] is True
    assert finding.evidence["compared_size"] == [200, 100]
    assert VisualDetector().detect(context(store, snapshot(), snapshot())) == []


# --- tls -----------------------------------------------------------------------------


def tls(**kw):
    defaults = {
        "host": "shop.example",
        "port": 443,
        "issuer": "CN=Good CA",
        "fingerprint_sha256": "aa",
        "not_after": "2027-06-01T00:00:00+00:00",
        "trusted": True,
    }
    defaults.update(kw)
    return TlsInfo(**defaults)


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (tls(), tls(), set()),
        (tls(), tls(issuer="CN=Other CA", fingerprint_sha256="bb"), {"issuer_changed"}),
        (tls(), tls(fingerprint_sha256="bb"), {"certificate_changed"}),
        (tls(), tls(trusted=False), {"untrusted"}),
        (tls(), tls(not_after="2026-12-01T00:00:00+00:00"), {"expiring"}),
        (tls(), tls(error="ConnectionRefusedError"), {"tls_error"}),
        (tls(error="x"), tls(error="y"), set()),
        (None, tls(), set()),
    ],
)
def test_tls(store, before, after, expected):
    found = TlsDetector().detect(context(store, snapshot(tls=before), snapshot(tls=after)))
    assert {f.change_type for f in found} == expected


def test_tls_expired_flag(store):
    expired = tls(not_after="2026-11-01T00:00:00+00:00")
    (finding,) = TlsDetector().detect(context(store, snapshot(tls=tls()), snapshot(tls=expired)))
    assert finding.attributes["expired"] is True
    assert NOW.year == 2026
    assert TlsDetector().detect(context(store, snapshot(tls=tls()), snapshot(tls=None))) == []


# --- registry ------------------------------------------------------------------------


class Boom:
    name = "boom"

    def detect(self, ctx):
        raise RuntimeError("kaput")


def test_crashing_detector_becomes_a_finding(store):
    findings = run_detectors(context(store, snapshot(), snapshot()), (Boom(),))
    (finding,) = findings
    assert (finding.detector, finding.change_type, finding.subject) == (
        "blink",
        "detector_failed",
        "boom",
    )
    assert finding.target == "checkout"
    assert finding.evidence["error"] == "kaput"


def test_registry_names_are_unique():
    names = [d.name for d in DETECTORS]
    assert len(names) == len(set(names)) == 7


def test_region_box_missing_does_not_crash(store):
    current = snapshot(payment_region=RegionCapture("#payment", False))
    assert FormsDetector().detect(context(store, snapshot(), current)) == []
