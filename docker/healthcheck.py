#!/usr/bin/env python3
"""Container healthcheck: GET $BLINK_HEALTHCHECK_URL (loopback only) and expect HTTP 200."""

from __future__ import annotations

import os
import sys
import urllib.request
from urllib.parse import urlsplit


def main() -> int:
    url = os.environ.get("BLINK_HEALTHCHECK_URL", "").strip()
    if not url:
        import blink_visual  # noqa: F401  # the package imports: good enough

        return 0
    if urlsplit(url).hostname not in {"127.0.0.1", "localhost", "::1"}:
        print(f"refusing non-loopback healthcheck URL {url}", file=sys.stderr)
        return 1
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310  # nosec B310
            return 0 if response.status == 200 else 1
    except OSError as exc:
        print(f"unhealthy: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
