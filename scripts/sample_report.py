"""Generate the published sample signed report from the localhost lab.

Usage: python scripts/sample_report.py OUT_DIR

Runs the lab in-process (127.0.0.1 only), records a baseline, approves the lab's scripts,
injects a third-party script, scans, and writes report.html, report.pdf, report.json, the
ledger public key and the verify-report output into OUT_DIR. Needs the [capture,server] extras
and Chromium.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from blink_visual.cli import main
from blink_visual.lab import lab_target
from blink_visual.lab.server import Lab
from blink_visual.store.ledger import key_path


def run(*argv: str) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    if code not in (0, 1):
        sys.stderr.write(out.getvalue())
        raise SystemExit(f"blink {' '.join(argv)} exited {code}")
    return out.getvalue()


def generate(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    home = Path.cwd()
    with (
        tempfile.TemporaryDirectory(prefix="blink-sample-", ignore_cleanup_errors=True) as tmp,
        Lab() as lab,
    ):
        work = Path(tmp)
        os.chdir(work)
        try:
            _scan_and_report(lab, work, out_dir)
        finally:
            os.chdir(home)


def _scan_and_report(lab: Lab, work: Path, out_dir: Path) -> None:
    import yaml

    run("init", "--lab")
    config = yaml.safe_load((work / "blink.yaml").read_text("utf-8"))
    config["targets"] = [lab_target(lab.checkout_url)]
    (work / "blink.yaml").write_text(yaml.safe_dump(config, sort_keys=False), "utf-8")
    run("baseline", "--reason", "sample report: known-good lab checkout")
    run("inventory", "--sync")
    listing = json.loads(run("inventory", "--json"))
    pending = sorted({r["id"] for r in listing["scripts"] if not r["approved"]})
    run(
        "approve",
        *pending,
        "--justification",
        "Lab checkout script",
        "--owner",
        "web-team",
        "--approved-by",
        "sample-report",
    )
    run("scan")
    lab.set_scenario("new_third_party_script")
    run("scan")
    run("report", "--days", "1", "--out", str(work / "report"))
    for name in ("report.html", "report.pdf", "report.json"):
        shutil.copy2(work / "report" / name, out_dir / name)
    shutil.copy2(key_path(work / ".blink").with_suffix(".pub"), out_dir / "ledger_ed25519.pub")
    verify = run(
        "verify-report",
        str(out_dir / "report.json"),
        "--public-key",
        str(out_dir / "ledger_ed25519.pub"),
    )
    (out_dir / "verify.txt").write_text(verify, encoding="utf-8")
    print(verify, end="")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    generate(Path(sys.argv[1]).resolve())
