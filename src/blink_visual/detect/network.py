"""Network detector: request destinations (origins) that the baseline never contacted."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit, urlunsplit

from ..capture.models import RequestRecord, Snapshot
from ..findings import Finding
from .base import DetectionContext

EXFIL_TYPES = frozenset({"ping", "beacon", "websocket", "eventsource"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def destinations(snapshot: Snapshot) -> dict[str, list[RequestRecord]]:
    grouped: dict[str, list[RequestRecord]] = defaultdict(list)
    for request in snapshot.requests:
        origin = request.origin
        if origin is not None:
            grouped[origin].append(request)
    return dict(grouped)


def _without_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


class NetworkDetector:
    name = "network"

    def detect(self, ctx: DetectionContext) -> list[Finding]:
        before = destinations(ctx.baseline)
        after = destinations(ctx.current)
        findings: list[Finding] = []
        for origin in sorted(set(after) - set(before)):
            requests = after[origin]
            methods = sorted({r.method.upper() for r in requests})
            types = sorted({r.resource_type for r in requests})
            sends_data = any(
                r.method.upper() not in SAFE_METHODS or r.resource_type in EXFIL_TYPES
                for r in requests
            )
            findings.append(
                Finding(
                    detector=self.name,
                    change_type="new_destination",
                    subject=origin,
                    title=f"New network destination {origin} ({', '.join(methods)}; "
                    f"{', '.join(types)})",
                    attributes={
                        "sends_data": sends_data,
                        "websocket": "websocket" in types,
                        "beacon": bool({"ping", "beacon"} & set(types)),
                        "request_count": len(requests),
                    },
                    evidence={
                        "methods": methods,
                        "resource_types": types,
                        # Query strings are dropped: they can carry tokens or personal data.
                        "urls": sorted({_without_query(r.url) for r in requests})[:20],
                    },
                )
            )
        for origin in sorted(set(before) - set(after)):
            findings.append(
                Finding(
                    detector=self.name,
                    change_type="destination_removed",
                    subject=origin,
                    title=f"Network destination no longer contacted: {origin}",
                    evidence={"request_count": len(before[origin])},
                )
            )
        return findings
