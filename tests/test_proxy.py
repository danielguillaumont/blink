"""BLINK_PROXY: Chromium proxy settings from the environment (no network)."""

from __future__ import annotations

import pytest

from blink_visual.capture.browser import proxy_settings
from blink_visual.errors import CaptureError


def test_no_proxy_by_default():
    assert proxy_settings({}) is None
    assert proxy_settings({"BLINK_PROXY": "  "}) is None


def test_proxy_server_bypass_and_credentials():
    settings = proxy_settings(
        {
            "BLINK_PROXY": "http://proxy.internal:3128",
            "BLINK_PROXY_BYPASS": "localhost,.corp.example",
            "BLINK_PROXY_USERNAME": "svc-blink",
            "BLINK_PROXY_PASSWORD": "placeholder",
        }
    )
    assert settings == {
        "server": "http://proxy.internal:3128",
        "bypass": "localhost,.corp.example",
        "username": "svc-blink",
        "password": "placeholder",
    }


def test_proxy_without_scheme_defaults_to_http():
    assert proxy_settings({"BLINK_PROXY": "proxy.internal:3128"}) == {
        "server": "http://proxy.internal:3128"
    }


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("ftp://proxy:21", "must look like"),
        ("http://user:pw@proxy:3128", "BLINK_PROXY_USERNAME"),
    ],
)
def test_bad_proxy_values(value, message):
    with pytest.raises(CaptureError, match=message):
        proxy_settings({"BLINK_PROXY": value})
