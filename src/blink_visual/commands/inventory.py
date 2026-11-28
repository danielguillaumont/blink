"""``blink inventory``, ``blink approve`` and ``blink suggest-csp`` (PCI DSS 6.4.3)."""

from __future__ import annotations

import argparse
import getpass
import json
from typing import Any

from ..capture.models import ScriptRecord, Snapshot
from ..errors import BlinkError
from ..inventory import (
    Inventory,
    InventoryEntry,
    approve,
    entry_for,
    load_inventory,
    save_inventory,
    suggested_id,
    unique_scripts,
)
from ..project import Project
from ..store import Store
from .scan import _check_profiles, _targets_argument, select_targets


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    inventory = subparsers.add_parser(
        "inventory",
        parents=[common],
        help="List payment page scripts and their approval state",
        description=(
            "List the scripts in each target's baseline (or latest snapshot) with their "
            "approval state and static risk score. --sync adds unlisted scripts to "
            "blink.inventory.yaml as unapproved entries. Exit 1 with --check if any script "
            "is unapproved."
        ),
    )
    _targets_argument(inventory)
    inventory.add_argument(
        "--sync", action="store_true", help="add unlisted scripts to the inventory file"
    )
    inventory.add_argument(
        "--check", action="store_true", help="exit 1 when any script is not approved"
    )
    inventory.add_argument("--json", action="store_true", help="print machine-readable output")
    inventory.set_defaults(handler=run_inventory)

    approve_parser = subparsers.add_parser(
        "approve",
        parents=[common],
        help="Approve a script in the inventory with a justification and owner",
        description=(
            "Record an authorization for a script (PCI DSS 6.4.3). ID is an inventory id, as "
            "printed by `blink inventory` or by an inventory finding. A script seen in a "
            "snapshot but not yet listed is added first."
        ),
    )
    approve_parser.add_argument("ids", nargs="+", metavar="ID", help="inventory id(s)")
    approve_parser.add_argument("--justification", required=True, help="why the script is needed")
    approve_parser.add_argument("--owner", required=True, help="team or person responsible")
    approve_parser.add_argument(
        "--approved-by", default=None, help="who authorized it (default: the current OS user)"
    )
    approve_parser.add_argument(
        "--dynamic",
        action="store_true",
        help="authorize the URL but do not pin the content hash (content changes legitimately)",
    )
    approve_parser.add_argument("--notes", default=None, help="free-text notes")
    approve_parser.set_defaults(handler=run_approve)

    csp = subparsers.add_parser(
        "suggest-csp",
        parents=[common],
        help="Suggest a minimal CSP and SRI attributes from the approved inventory",
        description=(
            "Build script-src from approved inventory entries and connect-src from the "
            "baseline's requests, plus hardening directives and SRI <script> tags."
        ),
    )
    csp.add_argument("target", metavar="TARGET", help="target name")
    csp.add_argument("--profile", default=None, help="baseline profile (default: the first)")
    csp.add_argument("--json", action="store_true", help="print machine-readable output")
    csp.set_defaults(handler=run_suggest_csp)


def reference_snapshot(store: Store, target: str, profile: str) -> Snapshot | None:
    """The baseline snapshot, else the most recent snapshot, else ``None``."""
    snapshot_id = store.baseline_id(target, profile)
    if snapshot_id is None:
        ids = store.snapshot_ids(target, profile)
        snapshot_id = ids[-1] if ids else None
    return store.load_snapshot(snapshot_id) if snapshot_id else None


def _collect(
    project: Project, store: Store, names: list[str], profiles: list[str] | None
) -> list[tuple[ScriptRecord, str, str]]:
    """(script, page url, where) for every distinct script across the reference snapshots."""
    pairs: list[tuple[ScriptRecord, str]] = []
    where: dict[str, str] = {}
    for target in select_targets(project, names):
        for profile in target.profiles:
            if profiles and profile not in profiles:
                continue
            snap = reference_snapshot(store, target.name, profile)
            if snap is None:
                continue
            for script in snap.scripts:
                pairs.append((script, snap.final_url or snap.url))
                where.setdefault(script.key, f"{target.name} [{profile}]")
    return [(s, page, where[s.key]) for s, page in unique_scripts(pairs)]


def _load(project: Project) -> Inventory:
    return load_inventory(project.inventory_path) or Inventory()


def _risk(store: Store, script: ScriptRecord) -> int | None:
    from ..jsanalysis import analyze

    if script.sha256 is None:
        return None
    try:
        return analyze(store.get_blob(script.sha256)).score
    except BlinkError:
        return None


def run_inventory(args: argparse.Namespace) -> int:
    project = Project.load(args.config)
    _check_profiles(project, args.profiles)
    inventory = _load(project)
    rows: list[dict[str, Any]] = []
    added = 0
    with project.open_store() as store:
        scripts = _collect(project, store, args.targets, args.profiles)
        for script, page, where in scripts:
            entry = inventory.match(script)
            if entry is None and args.sync:
                entry = entry_for(script, page)
                if inventory.get(entry.id) is not None:
                    raise BlinkError(f"inventory id {entry.id} already exists for another script")
                inventory.scripts.append(entry)
                added += 1
            pinned_ok = entry is None or not entry.pinned or entry.expected_hash == script.sha384
            rows.append(
                {
                    "id": entry.id if entry else suggested_id(script),
                    "listed": entry is not None,
                    "approved": bool(entry and entry.approved),
                    "hash_matches": pinned_ok,
                    "type": entry.type if entry else entry_for(script, page).type,
                    "script": script.key,
                    "seen_in": where,
                    "sha384": script.sha384,
                    "risk_score": _risk(store, script),
                    "owner": entry.owner if entry else "",
                    "justification": entry.justification if entry else "",
                }
            )
    if args.sync and added:
        save_inventory(project.inventory_path, inventory)
    if args.json:
        print(json.dumps({"scripts": rows, "added": added}, indent=2))
    else:
        _print_rows(rows, scripts_found=bool(scripts))
        if args.sync:
            print(
                f"\nAdded {added} unapproved entr{'y' if added == 1 else 'ies'} to "
                f"{project.inventory_path}"
            )
    unapproved = [r for r in rows if not r["approved"] or not r["hash_matches"]]
    return 1 if args.check and unapproved else 0


def _print_rows(rows: list[dict[str, Any]], *, scripts_found: bool) -> None:
    if not scripts_found:
        print("No snapshots found. Run `blink baseline` (or `blink capture`) first.")
        return
    for row in rows:
        if not row["approved"]:
            state = "UNAPPROVED" if row["listed"] else "UNLISTED"
        else:
            state = "approved" if row["hash_matches"] else "HASH CHANGED"
        risk = "-" if row["risk_score"] is None else str(row["risk_score"])
        print(f"{state:<12} {row['type']:<12} risk {risk:>3}  {row['id']}")
        print(f"             {row['script'][:100]}")
        if row["justification"]:
            print(f"             {row['owner']}: {row['justification'][:90]}")


def run_approve(args: argparse.Namespace) -> int:
    project = Project.load(args.config)
    inventory = _load(project)
    approved_by = args.approved_by if args.approved_by is not None else getpass.getuser()
    pending: list[InventoryEntry] = []
    unknown: list[str] = []
    discovered: dict[str, InventoryEntry] | None = None
    for entry_id in args.ids:
        entry = inventory.get(entry_id)
        if entry is None:
            if discovered is None:
                discovered = _discover(project)
            entry = discovered.get(entry_id)
        if entry is None:
            unknown.append(entry_id)
            continue
        pending.append(
            approve(
                entry,
                justification=args.justification,
                owner=args.owner,
                approved_by=approved_by,
                dynamic=args.dynamic,
                notes=args.notes,
            )
        )
    if unknown:
        raise BlinkError(
            f"unknown inventory id(s): {', '.join(unknown)}",
            hint="run `blink inventory` to list ids, or `blink inventory --sync` to add them",
        )
    for entry in pending:
        inventory.upsert(entry)
    save_inventory(project.inventory_path, inventory)
    with project.open_store() as store:
        for entry in pending:
            store.ledger.append(
                "inventory.approved",
                {
                    "id": entry.id,
                    "url": entry.url,
                    "inline_sha384": entry.inline_sha384,
                    "expected_hash": entry.expected_hash,
                    "justification": entry.justification,
                    "owner": entry.owner,
                    "approved_by": entry.approved_by,
                },
                at=entry.approved_at or "",
            )
            pin = "content hash not pinned" if not entry.pinned else "content hash pinned"
            print(f"Approved {entry.id} ({pin}) by {entry.approved_by} at {entry.approved_at}")
    return 0


def _discover(project: Project) -> dict[str, InventoryEntry]:
    found: dict[str, InventoryEntry] = {}
    if not project.config.targets:
        return found
    with project.open_store() as store:
        for script, page, _ in _collect(project, store, [], None):
            entry = entry_for(script, page)
            found.setdefault(entry.id, entry)
    return found


def run_suggest_csp(args: argparse.Namespace) -> int:
    from ..csp_suggest import suggest_csp

    project = Project.load(args.config)
    target = project.config.target(args.target)
    profile = args.profile or target.profiles[0]
    if profile not in target.profiles:
        raise BlinkError(f"target {target.name} has no profile {profile!r}")
    inventory = load_inventory(project.inventory_path)
    if inventory is None:
        raise BlinkError(
            f"no inventory at {project.inventory_path}",
            hint="run `blink inventory --sync` and `blink approve` first",
        )
    with project.open_store() as store:
        snap = reference_snapshot(store, target.name, profile)
    if snap is None:
        raise BlinkError(
            f"no snapshot for {target.name} [{profile}]",
            hint=f"run `blink baseline {target.name}` first",
        )
    suggestion = suggest_csp(inventory, snap)
    if args.json:
        print(json.dumps(suggestion.to_dict(), indent=2))
        return 0
    print("Content-Security-Policy:")
    print(f"  {suggestion.header}")
    if suggestion.sri_tags:
        print("\nSRI attributes for pinned scripts:")
        for tag in suggestion.sri_tags:
            print(f"  {tag}")
    for note in suggestion.notes:
        print(f"\nnote: {note}")
    print(
        "\nReview before deploying: try it as Content-Security-Policy-Report-Only first, and "
        "add a nonce or hash for any approved inline script that changes per request."
    )
    return 0
