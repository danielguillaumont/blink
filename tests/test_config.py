from pathlib import Path

import pytest

from blink_visual.config import load_config, parse_config
from blink_visual.errors import ConfigError
from blink_visual.project import Project, adhoc_name


def target(**overrides):
    data = {"name": "checkout", "url": "https://shop.example/checkout"}
    data.update(overrides)
    return data


def test_minimal_config_defaults():
    config = parse_config({"targets": [target()]})
    t = config.target("checkout")
    assert t.profiles == ["desktop-chrome"]
    assert t.timeout_s == 30
    assert t.normalize.strip_attributes == ["nonce"]
    assert config.store == ".blink"
    assert config.profile("mobile-safari-ish").is_mobile


def test_empty_document_is_an_empty_config():
    assert parse_config(None).targets == []


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ({"targets": [target(url="ftp://x")]}, "targets.0.url: must be an absolute http"),
        ({"targets": [target(name="Bad Name")]}, "targets.0.name"),
        ({"targets": [target(timeout_s=0)]}, "timeout_s"),
        ({"targets": [target(), target()]}, "duplicate target names: checkout"),
        ({"targets": [target(profiles=["nope"])]}, "unknown profile(s) nope"),
        ({"targets": [target(typo=True)]}, "typo"),
        ({"version": 2}, "version"),
        (
            {"targets": [target(normalize={"regexes": [{"pattern": "("}]})]},
            "invalid regular expression",
        ),
        ([1, 2], "expected a mapping"),
    ],
)
def test_invalid_configs_have_actionable_messages(data, fragment):
    with pytest.raises(ConfigError) as error:
        parse_config(data)
    assert fragment in str(error.value)


def test_custom_profile_is_accepted():
    config = parse_config(
        {
            "profiles": {
                "tablet": {"viewport": {"width": 800, "height": 1000}, "user_agent": "Tablet"}
            },
            "targets": [target(profiles=["tablet", "desktop-chrome"])],
        }
    )
    assert config.profile("tablet").viewport.width == 800


def test_unknown_target_and_profile():
    config = parse_config({"targets": [target()]})
    with pytest.raises(ConfigError, match="unknown target 'x'"):
        config.target("x")
    with pytest.raises(ConfigError, match="unknown profile"):
        config.profile("x")


def test_load_config_errors(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found") as error:
        load_config(tmp_path / "missing.yaml")
    assert "blink init" in str(error.value)
    bad = tmp_path / "bad.yaml"
    bad.write_text("targets: [", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(bad)


def test_project_resolves_names_and_adhoc_urls(write_project):
    path = write_project([target()])
    project = Project.load(path)
    assert project.resolve_target("checkout").url == "https://shop.example/checkout"
    assert project.resolve_target("https://shop.example/checkout").name == "checkout"
    adhoc = project.resolve_target("http://127.0.0.1:8780/checkout")
    assert adhoc.name == "adhoc-127-0-0-1-8780"
    assert project.store_dir == (path.parent / ".blink").resolve()
    with pytest.raises(ConfigError, match="invalid target URL"):
        project.resolve_target("javascript://x")


def test_project_without_config(tmp_path: Path):
    project = Project.load(tmp_path / "blink.yaml", required=False)
    assert not project.exists
    with pytest.raises(ConfigError, match="cannot be resolved"):
        project.resolve_target("checkout")
    assert adhoc_name("https://Shop.Example/pay").startswith("adhoc-shop-example")
