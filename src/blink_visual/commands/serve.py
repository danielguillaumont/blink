"""``blink serve``: the local dashboard and API."""

from __future__ import annotations

import argparse
import contextlib
import sys
from typing import Any

from ..errors import MissingExtraError
from ..project import Project


def add_parser(subparsers: Any, common: argparse.ArgumentParser) -> None:
    serve = subparsers.add_parser(
        "serve",
        parents=[common],
        help="Run the local dashboard and API (127.0.0.1 by default)",
        description=(
            "Dashboard (targets, runs, findings, inventory, alerts, settings) and JSON API with "
            "OpenAPI docs at /docs. Non-GET requests need the bearer token from "
            ".blink/blink.token (or $BLINK_TOKEN). Bound to a non-loopback address, every "
            "page also needs a login."
        ),
    )
    serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8765, help="port (default: 8765)")
    serve.set_defaults(handler=run_serve)


def run_serve(args: argparse.Namespace) -> int:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        raise MissingExtraError("server", "blink serve") from None
    from ..server.run import DashboardServer
    from ..server.security import TOKEN_ENV, token_path

    project = Project.load(args.config)
    server = DashboardServer(project, host=args.host, port=args.port)
    print(f"Blink dashboard on {server.url}  (API docs: {server.url}/docs)")
    print(f"API token: {token_path(project.store_dir)} (or ${TOKEN_ENV})")
    if not server.loopback:
        print(
            f"warning: bound to {args.host}, reachable from the network; every page needs a "
            "login. Put it behind TLS.",
            file=sys.stderr,
        )
    print("Press Ctrl+C to stop.")
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()
    return 0
