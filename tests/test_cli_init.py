import pytest
import yaml

from blink_visual.cli import main
from blink_visual.config import load_config


def test_init_creates_project_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitignore").write_text("node_modules/", encoding="utf-8")
    assert main(["init", "--url", "https://shop.example/checkout", "--name", "shop"]) == 0
    config = load_config(tmp_path / "blink.yaml")
    assert config.targets[0].name == "shop"
    inventory = yaml.safe_load((tmp_path / "blink.inventory.yaml").read_text("utf-8"))
    assert inventory == {"version": 1, "scripts": []}
    assert (tmp_path / ".blink" / "blink.db").exists()
    assert ".blink/" in (tmp_path / ".gitignore").read_text("utf-8").splitlines()
    assert "Created:" in capsys.readouterr().out
    # Running again never overwrites, and the .gitignore entry is not duplicated.
    assert main(["init"]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
    assert (tmp_path / ".gitignore").read_text("utf-8").count(".blink/") == 1


def test_init_lab_and_empty(tmp_path, capsys):
    assert main(["init", "--lab", "--config", str(tmp_path / "lab" / "blink.yaml")]) == 0
    config = load_config(tmp_path / "lab" / "blink.yaml")
    assert config.targets[0].url == "http://127.0.0.1:8780/checkout"
    assert config.targets[0].profiles == ["desktop-chrome", "mobile-safari-ish"]
    assert main(["init", "--config", str(tmp_path / "empty" / "blink.yaml")]) == 0
    assert "Next:" in capsys.readouterr().out


def test_capture_without_config_or_url(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["capture", "checkout"]) == 2
    assert "blink init" in capsys.readouterr().err


def test_lab_list(capsys):
    assert main(["lab", "--list"]) == 0
    out = capsys.readouterr().out
    assert "noise_only" in out
    assert "overlay_form_added" in out


def test_lab_switches_a_running_lab(clean_lab, capsys):
    port = int(clean_lab.shop_origin.rsplit(":", 1)[1])
    assert main(["lab", "--port", str(port), "--scenario", "csp_removed"]) == 0
    assert clean_lab.state.scenario == "csp_removed"
    assert "csp_removed" in capsys.readouterr().out


def test_lab_scenario_choices_are_validated():
    with pytest.raises(SystemExit) as error:
        main(["lab", "--scenario", "steal_cards"])
    assert error.value.code == 2
