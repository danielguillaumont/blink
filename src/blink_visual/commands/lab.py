"""``blink lab``: run the local demo shop, or switch the scenario of a running lab."""

from __future__ import annotations

import argparse
import http.client
import json
from typing import Any

from ..errors import BlinkError, MissingExtraError


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    from ..lab.scenarios import DEFAULT_SCENARIO, SCENARIOS

    parser = subparsers.add_parser(
        "lab",
        help="Run the local demo shop with tamper scenarios (127.0.0.1 only)",
        description=(
            "Start the lab shop (port P), its simulated third-party CDN (P+1) and a localhost "
            "sink (P+2). If a lab is already running on P, switch its scenario instead."
        ),
        epilog="scenarios: " + ", ".join(SCENARIOS),
    )
    parser.add_argument(
        "--scenario", choices=list(SCENARIOS), default=None, help=f"default: {DEFAULT_SCENARIO}"
    )
    parser.add_argument("--port", type=int, default=8780, help="shop port (default: 8780)")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.set_defaults(handler=run)


def running_lab(port: int, scenario: str | None, *, timeout: float = 2.0) -> dict[str, Any] | None:
    """Talk to a lab already running on ``port``; ``None`` if there is none."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        path = "/__admin/scenario" + (f"?scenario={scenario}" if scenario else "")
        connection.request("POST" if scenario else "GET", path)
        response = connection.getresponse()
        body = response.read()
    except OSError:
        return None
    finally:
        connection.close()
    if response.status != 200:
        raise BlinkError(f"lab on port {port} rejected the request: {body.decode()[:200]}")
    try:
        data: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError:
        raise BlinkError(f"port {port} is in use by something that is not the Blink lab") from None
    return data


def run(args: argparse.Namespace) -> int:
    from ..lab.scenarios import DEFAULT_SCENARIO, SCENARIOS

    if args.list:
        for scenario in SCENARIOS.values():
            print(f"{scenario.name:<28} {scenario.description}")
        return 0
    running = running_lab(args.port, args.scenario)
    if running is not None:
        print(f"Lab on 127.0.0.1:{args.port} serves scenario '{running['scenario']}'.")
        return 0
    try:
        from ..lab.server import Lab
    except ImportError:
        raise MissingExtraError("server", "The lab") from None
    ports = (args.port, args.port + 1, args.port + 2)
    lab = Lab(ports=ports, scenario=args.scenario or DEFAULT_SCENARIO).start()
    print(f"Blink lab: {lab.checkout_url}  (scenario: {lab.state.scenario})")
    print(f"  CDN {lab.state.cdn_origin}  sink {lab.state.sink_origin}  (Ctrl+C to stop)")
    print(f"  switch scenario: blink lab --scenario NAME --port {args.port}")
    lab.wait()
    return 0
