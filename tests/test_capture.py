"""Phase 1 acceptance: deterministic capture of the in-process localhost lab."""

from __future__ import annotations

import io
import socket
import threading
import time
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from blink_visual.analysis import analyze_pixels
from blink_visual.capture.service import capture_target
from blink_visual.cli import main
from blink_visual.config import TargetConfig
from blink_visual.errors import EXIT_CAPTURE, CaptureError
from blink_visual.lab import lab_target
from blink_visual.project import Project

pytestmark = [pytest.mark.browser, pytest.mark.integration]


def png(store, digest: str) -> np.ndarray:
    with Image.open(io.BytesIO(store.get_blob(digest))) as image:
        return np.asarray(image.convert("RGB"))


def signature(snapshot):
    return {
        "scripts": sorted((s.key, s.sha384, s.integrity) for s in snapshot.scripts),
        "header_names": sorted(snapshot.headers),
        "security_headers": {
            k: v
            for k, v in snapshot.headers.items()
            if k in {"content-security-policy", "strict-transport-security", "x-frame-options"}
        },
        "forms": snapshot.forms,
        "iframes": snapshot.iframes,
        "dom_hash": snapshot.dom_hash,
        "cookies": [(c.name, c.http_only) for c in snapshot.cookies],
    }


@pytest.fixture
def lab_project(clean_lab, write_project):
    return Project.load(write_project([lab_target(clean_lab.checkout_url)]))


@pytest.mark.parametrize("profile", ["desktop-chrome", "mobile-safari-ish"])
def test_clean_capture_is_deterministic(lab_project, capturer, profile):
    target = lab_project.config.targets[0]
    with lab_project.open_store() as store:
        first, second = (
            capture_target(lab_project, target, store, profiles=[profile], capturer=capturer)[0]
            for _ in range(2)
        )
        assert first.id != second.id
        assert signature(first) == signature(second)
        assert first.warnings == ()
        for role in ("screenshot", "region_screenshot"):
            a, b = png(store, first.blobs[role]), png(store, second.blobs[role])
            assert a.shape == b.shape
            changed = analyze_pixels(a, b, threshold=0).pixels.changed_percentage
            assert changed <= 0.01, f"{role}: {changed:.4f}% changed"
        assert store.snapshot_ids(target.name, profile) == [first.id, second.id]
        assert store.load_snapshot(first.id) == first


def test_snapshot_contents(lab_project, capturer, clean_lab):
    target = lab_project.config.targets[0]
    with lab_project.open_store() as store:
        (snap,) = capture_target(
            lab_project, target, store, profiles=["desktop-chrome"], capturer=capturer
        )
        har = store.get_blob(snap.blobs["har"])
    cdn = clean_lab.state.cdn_origin
    scripts = {s.key: s for s in snap.scripts}
    widget = scripts[f"{cdn}/lib/widget.js"]
    assert widget.integrity == widget.sha384
    assert widget.initiator is not None
    assert scripts[f"{clean_lab.shop_origin}/static/app.js"].integrity is None
    assert sum(s.inline for s in snap.scripts) == 1
    (form,) = snap.forms
    assert form.action == f"{clean_lab.shop_origin}/pay"
    assert {i.autocomplete for i in form.inputs} >= {"cc-number", "cc-exp", "cc-csc"}
    assert snap.payment_region is not None
    assert snap.payment_region.found
    assert snap.tls is None  # the lab is plain http
    assert "set-cookie" not in snap.headers
    assert [c.name for c in snap.cookies] == ["lab_session"]
    assert b"lab_session=" not in har  # cookie values never reach the HAR
    assert snap.status == 200


def test_capture_records_tamper_signals(lab_project, capturer, clean_lab):
    target = lab_project.config.targets[0]
    clean_lab.set_scenario("hidden_iframe_added")
    with lab_project.open_store() as store:
        (snap,) = capture_target(
            lab_project, target, store, profiles=["desktop-chrome"], capturer=capturer
        )
    (iframe,) = snap.iframes
    assert iframe.src == f"{clean_lab.state.sink_origin}/frame"
    assert iframe.offscreen
    assert not iframe.visible


def test_unreachable_target_exits_3(tmp_path, monkeypatch, capsys):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    monkeypatch.chdir(tmp_path)
    assert main(["capture", f"http://127.0.0.1:{port}/checkout"]) == EXIT_CAPTURE
    assert "target unreachable" in capsys.readouterr().err


def test_hanging_target_times_out_within_budget(tmp_path, capturer):
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def accept_and_hang():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                accepted.append(listener.accept()[0])
            except TimeoutError:
                continue

    thread = threading.Thread(target=accept_and_hang, daemon=True)
    thread.start()
    project = Project.load(tmp_path / "blink.yaml", required=False)
    target = TargetConfig(name="hang", url=f"http://127.0.0.1:{port}/", timeout_s=2)
    try:
        with project.open_store() as store:
            started = time.monotonic()
            with pytest.raises(CaptureError, match="timed out after 2s") as error:
                capturer.capture(
                    target, "desktop-chrome", project.config.profile("desktop-chrome"), store
                )
            elapsed = time.monotonic() - started
    finally:
        stop.set()
        thread.join(2)
        for conn in accepted:
            conn.close()
        listener.close()
    assert error.value.exit_code == EXIT_CAPTURE
    assert elapsed < 2 + 1.5, f"took {elapsed:.1f}s for a 2s timeout"


def test_cli_capture_by_name(lab_project, monkeypatch, capsys):
    monkeypatch.chdir(lab_project.root)
    code = main(["capture", "lab-checkout", "--profile", "desktop-chrome"])
    assert code == 0, capsys.readouterr().err
    out = capsys.readouterr().out
    assert "Captured lab-checkout [desktop-chrome]" in out
    with lab_project.open_store() as store:
        assert len(store.snapshot_ids("lab-checkout")) == 1


def test_capture_unknown_profile_is_a_usage_error(lab_project, monkeypatch, capsys):
    monkeypatch.chdir(lab_project.root)
    assert main(["capture", "lab-checkout", "--profile", "nope"]) == 2
    assert "unknown profile" in capsys.readouterr().err


def test_capture_json_output(lab_project, monkeypatch, capsys):
    import json

    monkeypatch.chdir(lab_project.root)
    assert main(["capture", "lab-checkout", "--profile", "mobile-safari-ish", "--json"]) == 0
    (manifest,) = json.loads(capsys.readouterr().out)
    assert manifest["profile"] == "mobile-safari-ish"
    assert manifest["viewport"] == [390, 844]
    assert Path(lab_project.store_dir).exists()
