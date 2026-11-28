"""``blink init``: write ``blink.yaml``, an empty inventory and the ``.blink/`` store."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from ..config import CONFIG_FILENAME, parse_config
from ..errors import BlinkError
from ..project import Project
from ..store.ledger import generate_key, key_fingerprint

HEADER = (
    "# Blink configuration. Reference: docs/configuration.md\n"
    "# Every target is captured once per profile. Masks hide volatile regions from the visual\n"
    "# detector; normalize rules remove volatile values (CSRF tokens, timestamps) from the DOM.\n"
)
INVENTORY = (
    "# Blink script inventory (PCI DSS 6.4.3). Commit this file and review changes to it.\n"
    "# Populate it with `blink inventory` and `blink approve`.\n"
    "version: 1\n"
    "scripts: []\n"
)
GITIGNORE_ENTRY = ".blink/"


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "init",
        parents=[common],
        help="Write blink.yaml, an empty inventory and the local .blink/ store",
        description="Create a Blink project in the current directory (or next to --config).",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--url", help="checkout URL of the first target")
    source.add_argument(
        "--lab",
        action="store_true",
        help="configure the local lab checkout (http://127.0.0.1:8780/checkout)",
    )
    parser.add_argument("--name", default="checkout", help="name of the first target")
    parser.set_defaults(handler=run)


def build_config(args: argparse.Namespace) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    if args.lab:
        from ..lab import lab_target

        targets.append(lab_target("http://127.0.0.1:8780/checkout"))
    elif args.url:
        targets.append(
            {
                "name": args.name,
                "url": args.url,
                "profiles": ["desktop-chrome", "mobile-safari-ish"],
                "payment_region": "form",
                "masks": [],
            }
        )
    return {
        "version": 1,
        "store": ".blink",
        "inventory": "blink.inventory.yaml",
        "targets": targets,
    }


def ensure_gitignore(root: Path) -> bool:
    """Add ``.blink/`` to ``.gitignore``; return True if the file changed."""
    path = root / ".gitignore"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if any(line.strip() in {GITIGNORE_ENTRY, ".blink"} for line in existing.splitlines()):
        return False
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write(f"# Blink evidence store, keys and tokens\n{GITIGNORE_ENTRY}\n")
    return True


def run(args: argparse.Namespace) -> int:
    config_path = (args.config or Path(CONFIG_FILENAME)).absolute()
    if config_path.exists():
        raise BlinkError(
            f"{config_path} already exists; refusing to overwrite it",
            hint="edit it directly, or pass --config to create a project elsewhere",
        )
    data = build_config(args)
    parse_config(data, source="generated configuration")  # validate before writing
    config_path.parent.mkdir(parents=True, exist_ok=True)
    text = HEADER + yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    with config_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    project = Project.load(config_path)
    created = [str(config_path)]
    if not project.inventory_path.exists():
        with project.inventory_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(INVENTORY)
        created.append(str(project.inventory_path))
    with project.open_store():
        created.append(str(project.store_dir))
    key, public = generate_key(project.store_dir)
    created.append(f"{key} (ledger signing key, keep private; never commit it)")
    if ensure_gitignore(project.root):
        created.append(f"{project.root / '.gitignore'} (added {GITIGNORE_ENTRY})")
    print("Created:")
    for item in created:
        print(f"  {item}")
    pub = key.with_suffix(".pub")
    print()
    print(f"Ledger public key: {key_fingerprint(public)}")
    print(f"  Record it outside this host (for example in your repository): {pub}")
    if not data["targets"]:
        print("Next: add a target to blink.yaml, then run `blink capture <target>`.")
    return 0
