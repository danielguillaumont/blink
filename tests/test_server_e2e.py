"""Phase 5 acceptance in a real browser against the localhost lab and ``blink serve``.

- Playwright UI flows: approving a script, acknowledging an alert, opening a finding, with no
  CSP violations in the console.
- Dogfood: ``blink scan`` against ``blink serve`` itself reports zero header findings.
"""

from __future__ import annotations

import pytest
import yaml

from blink_visual.cli import main
from blink_visual.lab import lab_target
from blink_visual.project import Project

pytest.importorskip("fastapi")
pytestmark = [pytest.mark.browser, pytest.mark.integration]


@pytest.fixture
def dashboard(clean_lab, tmp_path, monkeypatch, capturer, capsys):
    from blink_visual.server.run import DashboardServer
    from blink_visual.server.security import load_token

    target = lab_target(clean_lab.checkout_url)
    target["profiles"] = ["desktop-chrome"]
    (tmp_path / "blink.yaml").write_text(yaml.safe_dump({"targets": [target]}), "utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BLINK_TOKEN", raising=False)
    assert main(["baseline"]) == 0
    assert main(["inventory", "--sync"]) == 0
    clean_lab.set_scenario("new_third_party_script")
    assert main(["scan", "--fail-on", "none"]) == 0
    clean_lab.set_scenario("clean")
    capsys.readouterr()
    project = Project.load(tmp_path / "blink.yaml")
    with DashboardServer(project) as server:
        yield server, load_token(project.store_dir), project


@pytest.fixture
def page(capturer):
    context = capturer.browser.new_context(service_workers="block")
    page = context.new_page()
    violations: list[str] = []
    page.on(
        "console",
        lambda msg: (
            violations.append(msg.text)
            if "Content Security Policy" in msg.text or "Refused to" in msg.text
            else None
        ),
    )
    page.csp_violations = violations  # type: ignore[attr-defined]
    yield page
    context.close()


def _unlock(page, url: str, token: str) -> None:
    page.goto(url)
    page.fill("#unlock-token", token)
    page.click("#unlock-form button[type=submit]")
    page.wait_for_selector("html.unlocked")


def test_ui_approve_a_script(dashboard, page):
    server, token, project = dashboard
    _unlock(page, f"{server.url}/inventory", token)
    row = page.locator("tr.inventory-row", has=page.locator("form.approve-form")).first
    row_id = row.get_attribute("id")
    row.locator("input[name=justification]").fill("Lab checkout UI")
    row.locator("input[name=owner]").fill("web-team")
    row.locator("input[name=approved_by]").fill("ui-tester")
    row.locator("button[type=submit]").click()
    approved = page.locator(f"#{row_id} .state")
    approved.wait_for()
    page.wait_for_function(
        "id => document.querySelector('#' + id + ' .state').textContent.trim() === 'approved'",
        arg=row_id,
    )
    assert approved.text_content().strip() == "approved", page.locator("#flash").text_content()
    assert "ui-tester" in page.locator(f"#{row_id}").text_content()
    saved = yaml.safe_load(project.inventory_path.read_text("utf-8"))
    assert any(s["approved_by"] == "ui-tester" for s in saved["scripts"])
    assert page.csp_violations == []


def test_ui_requires_the_token_for_changes(dashboard, page):
    server, _token, _project = dashboard
    page.goto(f"{server.url}/alerts")
    row = page.locator("tr.alert-row").first
    row.locator("input[name=by]").fill("nobody")
    row.locator("button", has_text="Acknowledge").click()
    flash = page.locator("#flash")
    flash.wait_for(state="visible")
    assert "token" in flash.text_content().lower()
    assert page.csp_violations == []


def test_ui_acknowledge_an_alert(dashboard, page):
    server, token, _project = dashboard
    _unlock(page, f"{server.url}/alerts", token)
    row = page.locator("tr.alert-row").first
    row_id = row.get_attribute("id")
    row.locator("input[name=by]").fill("ui-tester")
    row.locator("input[name=note]").fill("investigating")
    row.locator("button", has_text="Acknowledge").click()
    page.wait_for_function(
        "id => document.querySelector('#' + id + ' .state').textContent === 'acknowledged'",
        arg=row_id,
    )
    assert "by ui-tester: investigating" in page.locator(f"#{row_id}").text_content()
    assert page.csp_violations == []


def test_ui_open_a_finding(dashboard, page):
    server, _token, _project = dashboard
    page.goto(f"{server.url}/runs")
    page.locator("table.timeline a").first.click()
    page.wait_for_selector("ul.findings")
    page.locator("a.finding-link").first.click()
    page.wait_for_selector("text=Why it matters")
    assert page.locator("section.why p").first.text_content().strip()
    images = page.locator(".gallery img")
    if images.count():
        assert page.evaluate("img => img.naturalWidth > 0", images.first.element_handle())
    assert page.csp_violations == []


def test_scanning_blink_serve_reports_no_header_findings(dashboard, tmp_path, capsys):
    """Dogfood: Blink passes its own header checks."""
    import json

    server, _token, _project = dashboard
    dogfood = tmp_path / "dogfood"
    dogfood.mkdir()
    config = {"targets": [{"name": "blink-serve", "url": f"{server.url}/"}]}
    (dogfood / "blink.yaml").write_text(yaml.safe_dump(config), "utf-8")
    path = str(dogfood / "blink.yaml")
    assert main(["baseline", "-c", path]) == 0
    capsys.readouterr()
    main(["scan", "-c", path, "--json", "--fail-on", "none"])
    report = json.loads(capsys.readouterr().out)
    assert report["targets"][0]["status"] == "ok"
    headers = [f for f in report["findings"] if f["detector"] == "headers"]
    assert headers == [], headers
