"""Dashboard and API (FastAPI TestClient; no browser, no network)."""

from __future__ import annotations

import io
import json
from dataclasses import replace

import pytest
import yaml
from helpers import snapshot

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient
from PIL import Image

from blink_visual.capture.models import ScriptRecord
from blink_visual.detect.headers import HeadersDetector
from blink_visual.findings import Severity
from blink_visual.project import Project
from blink_visual.scan import ScanReport, TargetResult, _record, compare_snapshots
from blink_visual.server import create_app
from blink_visual.server.security import CSP, HEADERS

TOKEN = "t0ken-for-tests-only-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PAGE = "https://shop.example/checkout"


def _png(color: tuple[int, int, int]) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (40, 30), color).save(buffer, format="PNG")
    return buffer.getvalue()


def _script(store, url: str, body: bytes) -> ScriptRecord:
    import base64
    import hashlib

    sha384 = "sha384-" + base64.b64encode(hashlib.sha384(body).digest()).decode()
    return ScriptRecord(
        url=url,
        inline=False,
        frame_url=PAGE,
        sha384=sha384,
        sha256=store.put_blob(body, "text/javascript"),
        size=len(body),
    )


@pytest.fixture
def project(tmp_path):
    config = {
        "alerts": {
            "sinks": [
                {"name": "hook", "type": "webhook", "url": "https://hooks.example/SECRET"},
            ]
        },
        "targets": [{"name": "checkout", "url": PAGE}],
    }
    path = tmp_path / "blink.yaml"
    path.write_text(yaml.safe_dump(config), "utf-8")
    project = Project.load(path)
    with project.open_store() as store:
        store.ensure_target("checkout", PAGE)
        app_v1 = _script(store, f"{PAGE}/app.js", b"function a(){\n  return 1;\n}\n")
        app_v2 = _script(store, f"{PAGE}/app.js", b"function a(){\n  return 2;\n}\n")
        har = {
            "log": {
                "entries": [
                    {
                        "request": {"method": "GET", "url": f"{PAGE}/app.js?v=2"},
                        "response": {"status": 200, "content": {"mimeType": "text/javascript"}},
                    }
                ]
            }
        }
        har_blob = store.put_blob(json.dumps(har).encode(), "application/json")
        base = snapshot(
            id="snap-base",
            target="checkout",
            scripts=(app_v1,),
            blobs={"screenshot": store.put_blob(_png((255, 255, 255)), "image/png")},
        )
        headers = dict(base.headers)
        headers.pop("x-frame-options")
        current = replace(
            base,
            id="snap-current",
            scripts=(app_v2,),
            headers=headers,
            blobs={"screenshot": store.put_blob(_png((200, 0, 0)), "image/png"), "har": har_blob},
        )
        store.save_snapshot(base)
        store.save_snapshot(current)
        store.set_baseline("checkout", "desktop-chrome", base.id)
        findings = compare_snapshots(project, store, project.config.targets[0], base, current)
        report = ScanReport(
            run_id="run-test",
            started_at="2026-11-27T10:00:00.000Z",
            finished_at="2026-11-27T10:00:05.000Z",
            fail_on=Severity.HIGH,
            results=(
                TargetResult("checkout", "desktop-chrome", "ok", base.id, current.id, None, 2),
            ),
            findings=tuple(findings),
        )
        _record(store, report, kind="scan")
    return project


@pytest.fixture
def client(project):
    return TestClient(create_app(project, token=TOKEN))


@pytest.fixture
def api(project):
    """A cookie-less API client (no CSRF needed, bearer only)."""
    client = TestClient(create_app(project, token=TOKEN))
    client.cookies.clear()
    return client


def _finding(client, change_type: str) -> dict:
    run = client.get("/api/runs/run-test").json()
    return next(f for f in run["findings"] if f["change_type"] == change_type)


# --- security ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/runs",
        "/runs/run-test",
        "/alerts",
        "/inventory",
        "/settings",
        "/login",
        "/api/targets",
        "/healthz",
        "/openapi.json",
    ],
)
def test_security_headers_everywhere(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-security-policy"] == CSP
    for name, value in HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["cache-control"] == "no-store"
    assert "server" not in response.headers or "uvicorn" not in response.headers["server"]


def test_csrf_cookie_is_strict_and_http_only(client):
    cookie = client.get("/").headers["set-cookie"]
    assert "blink_csrf=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie or "SameSite=Strict" in cookie


def test_blink_passes_its_own_header_checks(client):
    """Dogfood (no browser): the header detector finds nothing on Blink's own headers."""
    headers = dict(client.get("/").headers.items())
    snap = snapshot(headers=headers)
    from blink_visual.detect.base import DetectionContext
    from blink_visual.detect.csp import parse_csp, weaknesses

    assert weaknesses(parse_csp(headers["content-security-policy"])) == set()
    ctx = DetectionContext(snap, snap, None, None, None)  # type: ignore[arg-type]
    assert HeadersDetector().detect(ctx) == []


def test_docs_page_pins_swagger_with_sri(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert 'integrity="sha384-' in response.text
    assert "<script>" not in response.text  # no inline script
    assert "https://cdn.jsdelivr.net" in response.headers["content-security-policy"]
    spec = client.get("/openapi.json").json()
    assert "/api/alerts/{alert_id}/{action}" in spec["paths"]
    assert "/api/inventory/{entry_id}/approve" in spec["paths"]


def test_non_get_requires_bearer_token(api):
    body = {"by": "alice"}
    assert api.post("/api/alerts/x/ack", json=body).status_code == 401
    wrong = {"Authorization": "Bearer nope"}
    assert api.post("/api/alerts/x/ack", json=body, headers=wrong).status_code == 401
    assert api.post("/api/alerts/x/ack", json=body, headers=AUTH).status_code == 404


def test_browser_requests_need_csrf(client):
    client.get("/")  # sets the CSRF cookie
    csrf = client.cookies.get("blink_csrf")
    body = {"by": "alice"}
    response = client.post("/api/alerts/x/ack", json=body, headers=AUTH)
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]
    ok = client.post("/api/alerts/x/ack", json=body, headers={**AUTH, "X-CSRF-Token": csrf})
    assert ok.status_code == 404  # past auth and CSRF; the alert does not exist


def test_non_loopback_requires_login(project):
    client = TestClient(create_app(project, token=TOKEN, loopback=False))
    page = client.get("/", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"] == "/login"
    assert client.get("/api/targets").status_code == 401
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/targets", headers=AUTH).status_code == 200
    login = client.get("/login")
    csrf = client.cookies.get("blink_csrf")
    assert 'name="csrf_token"' in login.text
    assert client.post("/login", data={"token": TOKEN}).status_code == 403  # no CSRF field
    bad = client.post("/login", data={"token": "wrong", "csrf_token": csrf})
    assert bad.status_code == 401
    assert "not valid" in bad.text
    good = client.post("/login", data={"token": TOKEN, "csrf_token": csrf}, follow_redirects=False)
    assert good.status_code == 303
    assert "blink_session=" in good.headers["set-cookie"]
    assert client.get("/").status_code == 200


# --- pages ------------------------------------------------------------------------------


def test_targets_and_runs_pages(client):
    home = client.get("/").text
    assert "checkout" in home
    assert "snap-base" in home
    runs = client.get("/runs").text
    assert "run-test" in runs
    run = client.get("/runs/run-test").text
    assert "Content of a script changed" in run or "hash_changed" in run


def test_finding_detail_shows_screenshots_diff_and_har(client):
    changed = _finding(client, "hash_changed")
    page = client.get(f"/findings/run-test/{changed['id']}").text
    assert "Why it matters" in page
    assert '<span class="del">-  return 1;</span>' in page
    assert '<span class="add">+  return 2;</span>' in page
    assert "Blink" in page
    assert f"{PAGE}/app.js" in page  # HAR excerpt, query string removed
    assert "?v=2" not in page
    assert page.count("/blobs/") == 2  # baseline and current screenshots

    headers = _finding(client, "header_removed")
    detail = client.get(f"/api/findings/run-test/{headers['id']}").json()
    xfo = next(h for h in detail["headers"] if h["name"] == "x-frame-options")
    assert xfo["changed"] is True
    assert xfo["after"] is None


def test_blobs_serve_images_only(client, project):
    changed = _finding(client, "hash_changed")
    image = client.get(f"/api/findings/run-test/{changed['id']}").json()["images"][0]["blob"]
    response = client.get(f"/blobs/{image}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    script_blob = changed["evidence"]["after_blob"]
    assert client.get(f"/blobs/{script_blob}").status_code == 404  # never serve captured JS


def test_settings_redacts_webhook_urls(client):
    page = client.get("/settings").text
    assert "SECRET" not in page
    assert "redacted" in page


def test_unknown_pages_are_404(client):
    assert client.get("/runs/nope").status_code == 404
    assert "Not found" in client.get("/runs/nope").text
    assert client.get("/api/runs/nope").status_code == 404
    assert client.get("/findings/run-test/nope").status_code == 404


def test_metrics_endpoint(client):
    text = client.get("/metrics").text
    assert "blink_scans_total" in text
    assert "blink_findings_total" in text


# --- alerts -------------------------------------------------------------------------------


def test_alert_actions_via_api(api):
    alerts = api.get("/api/alerts").json()
    assert alerts
    alert_id = alerts[0]["id"]
    acked = api.post(f"/api/alerts/{alert_id}/ack", json={"by": "alice"}, headers=AUTH)
    assert acked.status_code == 200
    assert acked.json()["state"] == "acknowledged"
    again = api.post(f"/api/alerts/{alert_id}/ack", json={"by": "alice"}, headers=AUTH)
    assert again.status_code == 400
    assert "cannot become acknowledged" in again.json()["detail"]
    missing = api.post(f"/api/alerts/{alert_id}/resolve", json={}, headers=AUTH)
    assert missing.status_code == 422
    assert (
        api.post(f"/api/alerts/{alert_id}/bogus", json={"by": "a"}, headers=AUTH).status_code == 404
    )
    accepted = api.post(
        f"/api/alerts/{alert_id}/accept", json={"by": "bob", "note": "CHG-1"}, headers=AUTH
    )
    assert accepted.json()["state"] == "accepted-change"
    assert api.get("/api/ledger").json()["ok"] is True


def test_alert_action_via_htmx_returns_a_row(client):
    client.get("/alerts")
    csrf = client.cookies.get("blink_csrf")
    alert_id = client.get("/api/alerts").json()[0]["id"]
    response = client.post(
        f"/api/alerts/{alert_id}/ack",
        data={"by": "carol", "note": "looking"},
        headers={**AUTH, "X-CSRF-Token": csrf, "HX-Request": "true"},
    )
    assert response.status_code == 200
    assert response.text.lstrip().startswith(f'<tr id="alert-{alert_id}"')
    assert "acknowledged" in response.text
    assert "by carol: looking" in response.text


# --- inventory -------------------------------------------------------------------------------


def test_inventory_page_and_approval(api, project):
    rows = api.get("/api/inventory").json()
    (row,) = rows
    assert row["listed"] is False
    assert row["approved"] is False
    body = {"justification": "Checkout UI", "owner": "web", "approved_by": "dana"}
    response = api.post(f"/api/inventory/{row['id']}/approve", json=body, headers=AUTH)
    assert response.status_code == 200, response.text
    approved = response.json()
    assert approved["approved"] is True
    assert approved["approved_by"] == "dana"
    saved = yaml.safe_load(project.inventory_path.read_text("utf-8"))
    assert saved["scripts"][0]["justification"] == "Checkout UI"
    ledger = api.get("/api/ledger").json()
    assert ledger["ok"] is True
    bad = api.post(f"/api/inventory/{row['id']}/approve", json={"owner": "x"}, headers=AUTH)
    assert bad.status_code == 422
    unknown = api.post("/api/inventory/nope/approve", json=body, headers=AUTH)
    assert unknown.status_code == 404


def test_inventory_approval_via_htmx_form(client):
    client.get("/inventory")
    csrf = client.cookies.get("blink_csrf")
    (row,) = client.get("/api/inventory").json()
    response = client.post(
        f"/api/inventory/{row['id']}/approve",
        data={"justification": "UI", "owner": "web", "approved_by": "eve", "dynamic": "true"},
        headers={**AUTH, "X-CSRF-Token": csrf, "HX-Request": "true"},
    )
    assert response.status_code == 200
    assert 'class="inventory-row"' in response.text
    assert "approved" in response.text
    assert "dynamic" in response.text
