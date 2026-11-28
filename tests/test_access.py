"""Per-target proxy and auth: config validation, resolution, HAR scrubbing and a lab e2e."""

from __future__ import annotations

import pytest

from blink_visual.capture.access import origin_of, resolve_access
from blink_visual.capture.har import REDACTED, scrub_har
from blink_visual.config import TargetConfig, parse_config
from blink_visual.errors import ConfigError
from blink_visual.serde import dumps


def target(**extra) -> TargetConfig:
    return TargetConfig(name="shop", url="https://shop.example:8443/checkout", **extra)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"proxy": {"server": "ftp://p:21"}}, "http://host:port"),
        ({"proxy": {"server": "http://u:pw@p:3128"}}, "username_env"),
        ({"proxy": {"server": "p:3128", "username_env": "U"}}, "both username_env"),
        ({"auth": {"type": "header", "header": "Bad Header", "value_env": "T"}}, "header name"),
        ({"auth": {"type": "header", "header": "Cookie", "value_env": "T"}}, "cannot be used"),
        ({"auth": {"type": "basic", "username_env": "1BAD", "password_env": "P"}}, "pattern"),
        ({"auth": {"type": "oauth"}}, "type"),
    ],
)
def test_invalid_proxy_and_auth_rejected(entry, message):
    with pytest.raises(ConfigError, match=message):
        parse_config({"targets": [{"name": "t", "url": "https://x.example/", **entry}]})


def test_origin_normalises_default_ports():
    assert origin_of("https://Shop.example:443/a?b") == "https://shop.example"
    assert origin_of("http://127.0.0.1:8780/x") == "http://127.0.0.1:8780"


def test_no_access_settings_by_default():
    access = resolve_access(target(), environ={})
    assert access.context_options == {}
    assert access.header is None


def test_basic_auth_is_scoped_to_the_target_origin():
    access = resolve_access(
        target(auth={"type": "basic", "username_env": "U", "password_env": "P"}),
        environ={"U": "svc", "P": "s3cret"},
    )
    assert access.context_options["http_credentials"] == {
        "username": "svc",
        "password": "s3cret",
        "origin": "https://shop.example:8443",
    }
    assert "s3cret" in access.secret_values
    assert "authorization" in access.secret_headers


def test_header_auth_only_matches_same_origin():
    access = resolve_access(
        target(auth={"type": "header", "header": "X-Staging", "value_env": "T", "prefix": "Tok "}),
        environ={"T": "abc123"},
    )
    assert access.header == ("X-Staging", "Tok abc123")
    matches = access.same_origin()
    assert matches("https://shop.example:8443/static/app.js")
    assert not matches("https://cdn.example/lib.js")
    assert not matches("http://shop.example:8443/")  # scheme matters
    assert {"abc123", "Tok abc123"} <= access.secret_values


def test_proxy_precedence_and_credentials():
    tgt = target(proxy={"server": "http://t-proxy:3128", "bypass": "localhost"})
    assert resolve_access(tgt, environ={}).context_options["proxy"] == {
        "server": "http://t-proxy:3128",
        "bypass": "localhost",
    }
    from blink_visual.config import ProxyConfig

    profile = ProxyConfig(server="socks5://eu-egress:1080", username_env="PU", password_env="PP")
    access = resolve_access(tgt, profile_proxy=profile, environ={"PU": "u", "PP": "p"})
    assert access.context_options["proxy"] == {
        "server": "socks5://eu-egress:1080",
        "username": "u",
        "password": "p",
    }
    assert "p" in access.secret_values


def test_missing_secret_env_is_an_actionable_config_error():
    with pytest.raises(ConfigError, match="STAGING_TOKEN") as error:
        resolve_access(
            target(auth={"type": "header", "value_env": "STAGING_TOKEN"}),
            environ={},
        )
    assert error.value.exit_code == 2
    assert "export STAGING_TOKEN" in (error.value.hint or "")


def test_har_scrubs_custom_auth_header_and_secret_values():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "headers": [
                            {"name": "X-Staging", "value": "Tok abc123"},
                            {"name": "X-Other", "value": "contains abc123 inside"},
                            {"name": "Accept", "value": "text/html"},
                        ],
                    },
                    "response": {"headers": []},
                }
            ]
        }
    }
    scrubbed = scrub_har(har, names={"x-staging"}, values={"abc123"})
    headers = {h["name"]: h["value"] for h in scrubbed["log"]["entries"][0]["request"]["headers"]}
    assert headers == {"X-Staging": REDACTED, "X-Other": REDACTED, "Accept": "text/html"}


# -- e2e against the lab -------------------------------------------------------------------------


@pytest.mark.browser
@pytest.mark.integration
@pytest.mark.parametrize(
    ("auth", "env"),
    [
        (
            {"type": "basic", "username_env": "LAB_USER", "password_env": "LAB_PASS"},
            {"LAB_USER": "lab", "LAB_PASS": "lab-staging-pass"},
        ),
        (
            {"type": "header", "header": "X-Lab-Token", "value_env": "LAB_TOKEN"},
            {"LAB_TOKEN": "lab-staging-token"},
        ),
    ],
    ids=["basic", "header"],
)
def test_protected_lab_checkout(clean_lab, capturer, tmp_path, monkeypatch, auth, env):
    from blink_visual.lab import lab_target
    from blink_visual.project import Project

    for name, value in env.items():
        monkeypatch.setenv(name, value)
    clean_lab.state.leaked_auth.clear()
    clean_lab.set_scenario("new_third_party_script")  # adds a CDN script the header must skip
    entry = lab_target(clean_lab.checkout_url.replace("/checkout", "/staging/checkout"))
    entry["auth"] = auth
    tgt = TargetConfig(**entry)
    project = Project.load(tmp_path / "blink.yaml", required=False)
    with project.open_store() as store:
        snap = capturer.capture(
            tgt, "desktop-chrome", project.config.profile("desktop-chrome"), store
        )
        har = store.get_blob(snap.blobs["har"]).decode("utf-8")
    assert snap.status == 200
    assert any(s.url and "/lib/widget.js" in s.url for s in snap.scripts)
    assert clean_lab.state.leaked_auth == []
    secret = next(iter(env.values())) if auth["type"] == "header" else "lab-staging-pass"
    assert secret not in har
    assert secret not in dumps(snap)

    # Without credentials the page is a 401, which still captures (and would diff loudly).
    for name in env:
        monkeypatch.delenv(name)
    with project.open_store() as store, pytest.raises(ConfigError, match="not set"):
        capturer.capture(tgt, "desktop-chrome", project.config.profile("desktop-chrome"), store)
