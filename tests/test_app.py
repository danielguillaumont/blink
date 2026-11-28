"""Streamlit smoke tests; install the optional UI extra to execute."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def test_demo_and_threshold():
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert app.metric[0].value != "0.000%"
    app.slider[0].set_value(255).run()
    assert not app.exception
    assert app.metric[0].value == "0.000%"
    assert app.metric[2].value == "0"


@pytest.mark.parametrize("mode", ["Split", "Blink", "Heatmap", "Side by side"])
def test_modes(mode):
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.radio[1].set_value(mode).run()
    assert not app.exception


def test_empty_upload_state():
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.radio[0].set_value("Your images").run()
    assert not app.exception
    assert len(app.info) == 1
    assert len(app.metric) == 0
