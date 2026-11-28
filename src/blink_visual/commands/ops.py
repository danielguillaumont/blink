"""``blink daemon``, ``blink verify-ledger`` and ``blink alerts``."""

from __future__ import annotations

import argparse
import getpass
import json
import signal
import textwrap
from pathlib import Path
from typing import Any

from ..errors import EXIT_FINDINGS, EXIT_OK, BlinkError, MissingExtraError
from ..project import Project


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    daemon = subparsers.add_parser(
        "daemon",
        parents=[common],
        help="Run scheduled scans, detect missed evaluations and deliver alerts",
        description=(
            "Scan each target on its schedule (blink.yaml `schedule:`; default weekly, daily "
            "recommended), retry failed captures, raise a finding when an evaluation is missed, "
            "and send alerts to the configured sinks. Logs are JSON lines on stderr."
        ),
    )
    daemon.add_argument(
        "--once", action="store_true", help="scan every target now, check the schedule, exit"
    )
    daemon.add_argument(
        "--concurrency", type=int, default=2, metavar="N", help="parallel scans (default: 2)"
    )
    daemon.add_argument(
        "--metrics-port",
        type=int,
        default=None,
        metavar="PORT",
        help="serve Prometheus /metrics on this port (off by default)",
    )
    daemon.add_argument(
        "--metrics-host",
        default="127.0.0.1",
        metavar="HOST",
        help="address for /metrics (default: 127.0.0.1)",
    )
    daemon.set_defaults(handler=run_daemon)

    verify = subparsers.add_parser(
        "verify-ledger",
        parents=[common],
        help="Check the tamper-evident run history",
        description=(
            "Recompute the ledger hash chain and verify the signed head. Exit 0 if intact, "
            "1 if any record was modified, deleted or reordered."
        ),
    )
    verify.add_argument(
        "--public-key",
        type=Path,
        default=None,
        metavar="FILE",
        help="expected public key (.pub file); default: the key next to the signing key",
    )
    verify.add_argument("--json", action="store_true", help="print machine-readable output")
    verify.set_defaults(handler=run_verify_ledger)

    alerts = subparsers.add_parser(
        "alerts",
        parents=[common],
        help="List alerts and move them through open → acknowledged → resolved",
        description=(
            "Alerts are findings deduplicated by fingerprint. `accept` records a legitimate "
            "change: it rebaselines the target/profile from the run that saw it."
        ),
    )
    actions = alerts.add_subparsers(dest="alert_action", metavar="ACTION")
    listing = actions.add_parser("list", parents=[common], help="list alerts (default)")
    listing.add_argument(
        "--state",
        action="append",
        choices=["open", "acknowledged", "resolved", "accepted-change"],
        help="filter by state (repeatable; default: open and acknowledged)",
    )
    listing.add_argument("--all", action="store_true", help="every state")
    listing.add_argument("--json", action="store_true", help="print machine-readable output")
    show = actions.add_parser("show", parents=[common], help="an alert and its history")
    show.add_argument("id", metavar="ALERT_ID")
    show.add_argument("--json", action="store_true", help="print machine-readable output")
    for name, help_text in (
        ("ack", "acknowledge: someone is looking at it"),
        ("resolve", "resolved: the cause was fixed"),
        ("accept", "accepted change: legitimate; rebaseline (needs --note)"),
        ("reopen", "reopen a resolved or accepted alert"),
    ):
        action = actions.add_parser(name, parents=[common], help=help_text)
        action.add_argument("id", metavar="ALERT_ID")
        action.add_argument("--by", default=None, help="who (default: the current OS user)")
        action.add_argument("--note", default="", help="why")
    alerts.set_defaults(handler=run_alerts)


def run_daemon(args: argparse.Namespace) -> int:
    try:
        import apscheduler  # noqa: F401
    except ImportError:
        raise MissingExtraError("server", "blink daemon") from None
    from ..daemon import Daemon

    project = Project.load(args.config)
    if not project.config.targets:
        raise BlinkError(f"no targets configured in {project.config_path}")
    if args.concurrency < 1:
        raise BlinkError("--concurrency must be at least 1")
    daemon = Daemon(project, concurrency=args.concurrency)
    if args.once:
        code: int = daemon.run_once()
        return code
    signal.signal(signal.SIGTERM, lambda *_: daemon.stop())
    return daemon.serve_forever(metrics_host=args.metrics_host, metrics_port=args.metrics_port)


def run_verify_ledger(args: argparse.Namespace) -> int:
    from ..store.ledger import key_fingerprint

    project = Project.load(args.config)
    public_key = None
    if args.public_key is not None:
        try:
            public_key = args.public_key.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise BlinkError(f"cannot read {args.public_key}: {exc.strerror or exc}") from None
    with project.open_store() as store:
        result = store.ledger.verify(public_key=public_key)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    elif result.ok:
        print(
            f"Ledger OK: {result.records} record(s), head {result.head_seq} signed by "
            f"{key_fingerprint(result.public_key) if result.public_key else 'nobody (empty)'}"
        )
    else:
        print(f"Ledger verification FAILED ({result.records} record(s)):")
        for problem in result.problems:
            print(f"  - {problem}")
    return EXIT_OK if result.ok else EXIT_FINDINGS


def run_alerts(args: argparse.Namespace) -> int:
    from ..alerts import ACCEPTED, ACKNOWLEDGED, OPEN, RESOLVED, AlertManager

    project = Project.load(args.config)
    action = args.alert_action or "list"
    with project.open_store() as store:
        manager = AlertManager(store)
        if action == "list":
            states = (
                None
                if getattr(args, "all", False)
                else (getattr(args, "state", None) or [OPEN, ACKNOWLEDGED])
            )
            alerts = manager.all(states)
            if getattr(args, "json", False):
                print(json.dumps([a.to_dict() for a in alerts], indent=2))
                return EXIT_OK
            if not alerts:
                print("No alerts.")
            for a in alerts:
                print(
                    f"{a.severity.label.upper():<8} {a.state:<15} {a.id}  "
                    f"{a.target} [{a.profile}] {a.detector}.{a.change_type} x{a.occurrences}"
                )
                print(textwrap.indent(textwrap.fill(a.title, 90), "         "))
            return EXIT_OK
        if action == "show":
            alert = manager.get(args.id)
            events = manager.events(args.id)
            if args.json:
                print(json.dumps({"alert": alert.to_dict(), "events": events}, indent=2))
                return EXIT_OK
            for key, value in alert.to_dict().items():
                print(f"{key:>14}: {value}")
            print("\nHistory:")
            for e in events:
                print(
                    f"  {e['at']}  {e['from_state'] or '-'} -> {e['to_state']}  by "
                    f"{e['actor']}  {e['note']}"
                )
            return EXIT_OK
        target = {"ack": ACKNOWLEDGED, "resolve": RESOLVED, "accept": ACCEPTED, "reopen": OPEN}
        actor = args.by if args.by is not None else getpass.getuser()
        alert = manager.transition(args.id, target[action], actor=actor, note=args.note)
        print(f"Alert {alert.id} is now {alert.state} (by {alert.updated_by})")
        if alert.state == ACCEPTED and alert.detector != "schedule":
            print(
                f"  {alert.target} [{alert.profile}] was rebaselined from run {alert.last_run_id}"
            )
    return EXIT_OK
