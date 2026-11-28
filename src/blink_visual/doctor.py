"""``blink doctor``: check that this host can run Blink, and say how to fix what is missing.

Each check is a small function returning a :class:`Check`; the command runs them in order and
skips checks that depend on an earlier failure (no config → no store checks).
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .apitoken import token_path
from .errors import BlinkError
from .project import Project
from .store.ledger import key_path

OK = "ok"
WARN = "warn"
FAIL = "fail"
MIN_PYTHON = (3, 11)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    fix: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_python(version: tuple[int, ...] | None = None) -> Check:
    current = tuple(version or sys.version_info[:3])
    text = ".".join(str(p) for p in current[:3])
    if current[:2] < MIN_PYTHON:
        return Check(
            "python", FAIL, f"Python {text}", "install Python 3.11 or newer (3.12 recommended)"
        )
    return Check("python", OK, f"Python {text}")


def _has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def check_extras(has: Callable[[str], bool] = _has) -> list[Check]:
    wanted = {
        "capture": (["playwright"], "baseline, scan, capture, daemon and report PDFs"),
        "server": (["fastapi", "uvicorn", "apscheduler"], "serve, daemon and lab"),
    }
    out = []
    for extra, (modules, used_by) in wanted.items():
        missing = [m for m in modules if not has(m)]
        if missing:
            out.append(
                Check(
                    f"extra:{extra}",
                    WARN,
                    f"not installed ({', '.join(missing)} missing); needed for {used_by}",
                    f'python -m pip install "blink-checkout[{extra}]"',
                )
            )
        else:
            out.append(Check(f"extra:{extra}", OK, "installed"))
    return out


def chromium_path() -> str | None:
    """The Chromium executable Playwright would launch, or ``None`` if Playwright is absent."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        return str(playwright.chromium.executable_path)


def check_chromium(locate: Callable[[], str | None] | None = None) -> Check:
    # sys.executable is the interpreter Blink runs in (pipx, venv or system), so this command
    # installs Chromium where Blink's Playwright will look for it.
    fix = f'"{sys.executable}" -m playwright install chromium   (Linux: add --with-deps)'
    if locate is None:
        if not _has("playwright"):
            return Check("chromium", WARN, "Playwright is not installed", fix)
        locate = chromium_path
    try:
        path = locate()
    except Exception as exc:  # the Playwright driver itself failed to start
        return Check("chromium", FAIL, f"Playwright could not start: {exc}", fix)
    if not path or not Path(path).exists():
        return Check("chromium", FAIL, f"Chromium is not installed (expected {path})", fix)
    return Check("chromium", OK, path)


def check_config(path: Path | None) -> tuple[Check, Project | None]:
    try:
        project = Project.load(path, required=False)
    except BlinkError as exc:
        return Check(
            "config", FAIL, str(exc).splitlines()[0], "fix blink.yaml (see docs/configuration.md)"
        ), None
    if not project.exists:
        return (
            Check(
                "config",
                WARN,
                f"{project.config_path} not found",
                "blink init --url https://staging.example.com/checkout",
            ),
            None,
        )
    targets = len(project.config.targets)
    detail = f"{project.config_path} ({targets} target{'s' if targets != 1 else ''})"
    if not targets:
        return Check(
            "config", WARN, detail, "add a target to blink.yaml or run blink init --url URL"
        ), project
    return Check("config", OK, detail), project


def check_store(project: Project) -> Check:
    store_dir = project.store_dir
    if not store_dir.exists():
        return Check(
            "store", WARN, f"{store_dir} does not exist yet", "blink init, then blink baseline"
        )
    probe = store_dir / ".doctor-write-test"
    try:
        probe.write_bytes(b"ok")
        probe.unlink()
    except OSError as exc:
        return Check(
            "store",
            FAIL,
            f"{store_dir} is not writable: {exc.strerror or exc}",
            "fix the directory permissions or set `store:` in blink.yaml",
        )
    try:
        with project.open_store() as store:
            result = store.db.query_one("PRAGMA integrity_check")
            version = store.db.schema_version
    except (BlinkError, sqlite3.Error) as exc:
        detail = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        return Check(
            "store",
            FAIL,
            f"cannot open the store database: {detail}",
            "restore .blink/ from backup",
        )
    if result is None or result[0] != "ok":
        return Check(
            "store",
            FAIL,
            f"SQLite integrity check failed: {result[0] if result else '?'}",
            "restore .blink/blink.db from backup",
        )
    return Check("store", OK, f"{store_dir} (schema v{version})")


def check_keys(project: Project) -> list[Check]:
    key = key_path(project.store_dir)
    out: list[Check] = []
    if not key.exists():
        out.append(
            Check(
                "ledger-key",
                WARN,
                f"{key} is missing",
                "blink init creates it (or restore it from backup if the ledger has records)",
            )
        )
    else:
        mode = key.stat().st_mode & 0o777
        if os.name == "posix" and mode & 0o077:
            out.append(
                Check(
                    "ledger-key",
                    FAIL,
                    f"{key} is readable by others (mode {mode:o})",
                    f"chmod 600 {key}",
                )
            )
        else:
            out.append(Check("ledger-key", OK, str(key)))
    if project.store_dir.exists():
        with project.open_store() as store:
            verification = store.ledger.verify()
        if verification.ok:
            out.append(Check("ledger", OK, f"{verification.records} records verified"))
        else:
            out.append(
                Check(
                    "ledger",
                    FAIL,
                    "; ".join(verification.problems[:3]),
                    "see docs/runbooks/alert-fired.md (treat as a possible compromise)",
                )
            )
    token = token_path(project.store_dir)
    if token.exists() or os.environ.get("BLINK_TOKEN"):
        out.append(Check("api-token", OK, "set" if not token.exists() else str(token)))
    else:
        out.append(
            Check("api-token", WARN, "no dashboard token yet", "blink init (or set BLINK_TOKEN)")
        )
    return out


def check_baselines(project: Project) -> Check:
    if not project.store_dir.exists():
        return Check("baselines", WARN, "no store yet", "blink baseline")
    with project.open_store() as store:
        have = {(b["target"], b["profile"]) for b in store.baselines()}
    missing = [
        f"{t.name} [{p}]"
        for t in project.config.targets
        for p in t.profiles
        if (t.name, p) not in have
    ]
    if missing:
        shown = ", ".join(missing[:4]) + (" …" if len(missing) > 4 else "")
        return Check("baselines", WARN, f"missing for {shown}", "blink baseline --if-missing")
    return Check("baselines", OK, f"{len(have)} recorded")


def run_checks(config_path: Path | None, *, browser: bool = True) -> list[Check]:
    checks = [check_python(), *check_extras()]
    if browser:
        checks.append(check_chromium())
    config, project = check_config(config_path)
    checks.append(config)
    if project is not None:
        store = check_store(project)
        checks.append(store)
        if store.status != FAIL:
            checks.extend(check_keys(project))
            if project.config.targets:
                checks.append(check_baselines(project))
    return checks
