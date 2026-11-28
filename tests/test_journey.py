"""Synthetic journeys: config validation, test data, order safety and lab end-to-end runs."""

from __future__ import annotations

import json

import pytest
import yaml

from blink_visual.canary import TEST_BIN, Canary, luhn_valid
from blink_visual.config import TargetConfig, parse_config
from blink_visual.errors import ConfigError, JourneyStepError
from blink_visual.journey.data import Resolver, check_template

URL = "http://127.0.0.1:8780/shop"


def target(journey, **extra) -> TargetConfig:
    return TargetConfig(name="shop", url=URL, journey=journey, **extra)


def config_error(journey, **extra) -> str:
    with pytest.raises(ConfigError) as error:
        parse_config({"targets": [{"name": "shop", "url": URL, "journey": journey, **extra}]})
    return str(error.value)


# -- config -------------------------------------------------------------------------------------


def test_shorthand_and_mapping_forms():
    tgt = target(
        [
            {"goto": "/shop"},
            {"click": "#add", "timeout_s": 5},
            {"fill": {"selector": "#email", "value": "{{faker.email}}"}, "frame": "#iframe"},
            {"press": "Enter"},
            {"press": {"selector": "#q", "key": "Tab"}},
            {"wait_ms": 200},
            {"capture": None},
            {"capture": "payment"},
        ]
    )
    steps = tgt.journey
    assert [s.action for s in steps][:3] == ["goto", "click", "fill"]
    assert steps[1].timeout_s == 5
    assert steps[2].frame == "#iframe"
    assert steps[3].key == "Enter" and steps[3].selector is None
    assert steps[4].selector == "#q"
    assert steps[6].name is None and steps[7].name == "payment"
    assert steps[2].describe() == "fill #email in frame #iframe"


@pytest.mark.parametrize(
    ("journey", "message"),
    [
        ([{"click": "#a", "goto": "/"}], "exactly one action"),
        ([{"teleport": "/"}], "exactly one action"),
        ([{"fill": "#x"}], "needs value"),
        ([{"select": {"selector": "#x"}}], "needs value"),
        ([{"wait_ms": 120_000}], "less than or equal"),
        ([{"fill": {"selector": "#x", "value": "{{canary.iban}}"}}], "unknown canary field"),
        ([{"fill": {"selector": "#x", "value": "{{faker.ssn}}"}}], "unknown faker field"),
        ([{"fill": {"selector": "#x", "value": "{{test_data.nope}}"}}], "unknown test_data key"),
        ([{"fill": {"selector": "#x", "value": "{{secrets.x}}"}}], "unknown placeholder"),
        ([{"fill": {"selector": "#x", "value": "{{ broken"}}], "malformed placeholder"),
        ([{"capture": "a"}, {"capture": "a"}], "duplicate capture name"),
    ],
)
def test_invalid_steps(journey, message):
    assert message in config_error(journey)


def test_submit_requires_test_mode():
    message = config_error([{"submit": "#place-order"}])
    assert "test_mode: true" in message
    assert target([{"submit": "#place-order"}], test_mode=True).journey[0].action == "submit"


@pytest.mark.parametrize(
    "selector",
    [
        "#place-order",
        "button.place_order",
        "#pay-now",
        ".checkout-submit",
        "button[type=submit]",
        "#confirm-payment",
        "#buy-now",
        ".pay-button",
    ],
)
def test_order_like_clicks_are_rejected_without_test_mode(selector):
    message = config_error([{"click": selector}])
    assert "looks like the final order submission" in message
    assert target([{"click": selector, "safe": True}]).journey[0].safe
    assert target([{"click": selector}], test_mode=True)


@pytest.mark.parametrize("selector", ["#add-to-cart", "#continue-to-payment", "#go-to-details"])
def test_ordinary_clicks_are_allowed(selector):
    assert target([{"click": selector}]).journey[0].selector == selector


def test_test_data_templates_are_checked():
    assert "test_data.pw" in config_error([], test_data={"pw": "{{test_data.other}}"})
    tgt = target(
        [{"fill": {"selector": "#e", "value": "{{test_data.email}}"}}],
        test_data={"email": "{{faker.email}}", "password": "{{env.SHOP_PASSWORD}}"},
    )
    assert tgt.test_data["password"] == "{{env.SHOP_PASSWORD}}"


def test_check_template_accepts_plain_text():
    check_template("plain value, no placeholders", set())


# -- test data -----------------------------------------------------------------------------------


def test_canary_is_luhn_valid_test_range_and_unique():
    canaries = [Canary.generate() for _ in range(50)]
    for canary in canaries:
        assert canary.pan.startswith(TEST_BIN) and len(canary.pan) == 16
        assert luhn_valid(canary.pan)
        assert canary.email.endswith("@blink.invalid")
        assert canary.token in canary.name.lower() or canary.token.upper() in canary.name
    assert len({c.pan for c in canaries}) == 50
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")


def test_resolver_stable_within_a_run_and_env_secrets_tracked():
    resolver = Resolver(
        test_data={"email": "{{faker.email}}", "pw": "{{env.SHOP_PW}}"},
        target="shop",
        environ={"SHOP_PW": "hunter2"},
    )
    email = resolver.resolve("{{test_data.email}}")
    assert email == resolver.resolve("{{ faker.email }}")
    assert resolver.resolve("card {{canary.pan}}") == f"card {resolver.canary.pan}"
    assert resolver.resolve("{{test_data.pw}}") == "hunter2"
    assert resolver.secrets_used == {"hunter2"}
    other = Resolver(test_data={}, target="shop")
    assert other.canary.pan != resolver.canary.pan


def test_resolver_missing_env_is_actionable():
    resolver = Resolver(test_data={}, target="shop", environ={})
    with pytest.raises(ConfigError, match="SHOP_PW") as error:
        resolver.resolve("{{env.SHOP_PW}}")
    assert "export SHOP_PW" in (error.value.hint or "")


def test_recipes_are_valid_configs():
    from pathlib import Path

    docs = Path(__file__).resolve().parents[1] / "docs" / "recipes"
    for recipe in ("woocommerce.md", "magento.md"):
        text = (docs / recipe).read_text(encoding="utf-8")
        block = text.split("```yaml", 1)[1].split("```", 1)[0]
        config = parse_config(yaml.safe_load(block))
        assert config.targets[0].journey, recipe
        assert not config.targets[0].test_mode, f"{recipe} must not place orders"


# -- lab end to end ------------------------------------------------------------------------------

browser = [pytest.mark.browser, pytest.mark.integration]


@pytest.fixture
def journey_project(clean_lab, tmp_path):
    from blink_visual.lab import lab_journey_target
    from blink_visual.project import Project

    entry = lab_journey_target(clean_lab.shop_origin)
    (tmp_path / "blink.yaml").write_text(yaml.safe_dump({"targets": [entry]}), "utf-8")
    return Project.load(tmp_path / "blink.yaml")


@pytest.mark.parametrize("profile", ["desktop-chrome", "mobile-safari-ish"])
@pytest.mark.browser
@pytest.mark.integration
def test_lab_journey_reaches_payment_on_both_profiles(journey_project, capturer, profile):
    from blink_visual.scan import establish_baseline, scan

    target = journey_project.config.targets[0]
    with journey_project.open_store() as store:
        (snap,) = establish_baseline(journey_project, store, target, capturer, profiles=[profile])
        assert snap.final_url.endswith("/shop/checkout")
        assert any(f.id == "checkout-form" for f in snap.forms)
        assert snap.journey is not None
        assert [s.status for s in snap.journey.steps] == ["ok"] * len(target.journey)
        assert [(s.name, s.primary) for s in snap.journey.states] == [
            ("cart", False),
            ("payment", True),
        ]
        assert snap.journey.blocked_submissions == 0
        assert any(s.url and s.url.endswith("/lib/widget.js") for s in snap.scripts)
        # Filled values are run-specific, never stored; the canary only lives in the page.
        dumped = json.dumps([s.description for s in snap.journey.steps])
        assert "{{canary.pan}}" not in dumped  # descriptions name selectors, not values
        report = scan(journey_project, store, [target], capturer, profiles=[profile])
    assert report.exit_code == 0, [f.title for f in report.findings]
    assert report.findings == ()


@pytest.mark.browser
@pytest.mark.integration
def test_empty_cart_redirect_without_journey_is_actionable(clean_lab, tmp_path, capsys):
    from blink_visual.cli import main
    from blink_visual.lab import lab_target

    entry = lab_target(f"{clean_lab.shop_origin}/shop/checkout", name="no-journey")
    entry["profiles"] = ["desktop-chrome"]
    (tmp_path / "blink.yaml").write_text(yaml.safe_dump({"targets": [entry]}), "utf-8")
    assert main(["capture", "no-journey", "--config", str(tmp_path / "blink.yaml")]) == 3
    err = capsys.readouterr().err
    assert "redirected to" in err and "/shop/cart?empty=1" in err
    assert "add a `journey:`" in err


@pytest.mark.browser
@pytest.mark.integration
def test_step_failure_becomes_a_finding_with_screenshot(journey_project, capturer, tmp_path):
    from blink_visual.project import Project
    from blink_visual.scan import establish_baseline, scan

    target = journey_project.config.targets[0]
    with journey_project.open_store() as store:
        establish_baseline(journey_project, store, target, capturer, profiles=["desktop-chrome"])
    raw = yaml.safe_load(journey_project.config_path.read_text("utf-8"))
    raw["targets"][0]["journey"][4] = {"click": "#checkout-button-renamed", "timeout_s": 1}
    journey_project.config_path.write_text(yaml.safe_dump(raw), "utf-8")
    project = Project.load(journey_project.config_path)
    broken = project.config.targets[0]
    with project.open_store() as store:
        report = scan(project, store, [broken], capturer, profiles=["desktop-chrome"])
        (finding,) = report.findings
        assert report.exit_code == 3
        assert (finding.detector, finding.change_type) == ("journey", "step_failed")
        assert finding.severity.label == "high"
        assert finding.evidence["step"] == 5
        assert finding.evidence["url"].endswith("/shop/cart")
        assert store.get_blob(finding.evidence["screenshot_blob"])[:4] == b"\x89PNG"
        with pytest.raises(JourneyStepError, match="journey step 5"):
            capturer.capture(
                broken, "desktop-chrome", project.config.profile("desktop-chrome"), store
            )


@pytest.mark.browser
@pytest.mark.integration
def test_payment_form_submission_is_blocked_without_test_mode(journey_project, capturer):
    raw = yaml.safe_load(journey_project.config_path.read_text("utf-8"))
    steps = raw["targets"][0]["journey"]
    steps.insert(-1, {"press": {"selector": "input[autocomplete=cc-number]", "key": "Enter"}})
    tgt = TargetConfig(**raw["targets"][0])
    with journey_project.open_store() as store:
        snap = capturer.capture(
            tgt, "desktop-chrome", journey_project.config.profile("desktop-chrome"), store
        )
    assert snap.final_url.endswith("/shop/checkout")  # still on the payment page
    assert snap.journey is not None and snap.journey.blocked_submissions == 1
    assert any("blocked 1 payment form submission" in w for w in snap.warnings)


@pytest.mark.browser
@pytest.mark.integration
def test_submit_runs_only_in_test_mode(journey_project, capturer):
    raw = yaml.safe_load(journey_project.config_path.read_text("utf-8"))
    raw["targets"][0]["test_mode"] = True
    raw["targets"][0]["journey"] += [{"submit": "#checkout-form button[type=submit]"}]
    raw["targets"][0]["wait_for"] = None
    raw["targets"][0]["payment_region"] = None
    tgt = TargetConfig(**raw["targets"][0])
    with journey_project.open_store() as store:
        snap = capturer.capture(
            tgt, "desktop-chrome", journey_project.config.profile("desktop-chrome"), store
        )
    assert snap.journey is not None and snap.journey.test_mode
    assert snap.journey.steps[-1].action == "submit"
    assert snap.journey.steps[-1].url and snap.journey.steps[-1].url.endswith("/pay")


# -- blink record ---------------------------------------------------------------------------------


def test_record_converts_codegen_and_drops_order_clicks(tmp_path, capsys):
    from pathlib import Path

    from blink_visual.cli import main
    from blink_visual.journey.record import codegen_to_steps

    source = (Path(__file__).parent / "fixtures" / "codegen_lab.py.txt").read_text("utf-8")
    steps = codegen_to_steps(source)
    real = [s for s in steps if isinstance(s, dict)]
    comments = [s for s in steps if isinstance(s, str)]
    assert real[0] == {"goto": "http://127.0.0.1:8780/shop"}
    assert real[1] == {"click": 'role=button[name="Add to cart"]'}
    assert {"fill": {"selector": 'internal:label="E-mail"i', "value": "{{faker.email}}"}} in real
    assert {
        "fill": {"selector": "#number", "value": "{{canary.pan}}"},
        "frame": "iframe[name=card]",
    } in real
    assert {"select": {"selector": "#country", "value": "GB"}} in real
    assert {"press": {"selector": '[placeholder="12/34"]', "key": "Tab"}} in real
    assert not any("pay-button" in str(s) for s in real)
    assert any(c.startswith("# REMOVED") and "pay-button" in c for c in comments)
    assert any(c.startswith("# TODO unsupported: expect(") for c in comments)
    assert "4242" not in str(real) and "someone@real.example" not in str(real)

    out = tmp_path / "draft.yaml"
    fixture = Path(__file__).parent / "fixtures" / "codegen_lab.py.txt"
    code = main(
        ["record", "http://127.0.0.1:8780/shop", "--from-file", str(fixture), "--out", str(out)]
    )
    assert code == 0
    config = parse_config(yaml.safe_load(out.read_text("utf-8")))
    assert config.targets[0].journey[-1].action == "capture"


def test_record_rejects_bad_input(tmp_path, capsys):
    from blink_visual.cli import main

    assert main(["record", "ftp://x", "--from-file", str(tmp_path / "x.py")]) == 2
    bad = tmp_path / "bad.py"
    bad.write_text("page.goto(\n", encoding="utf-8")
    assert main(["record", "http://127.0.0.1:1/", "--from-file", str(bad)]) == 2
    assert "cannot parse" in capsys.readouterr().err
    assert main(["record", "http://127.0.0.1:1/", "--from-file", str(tmp_path / "nope.py")]) == 2
