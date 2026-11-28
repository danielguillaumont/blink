"""Scrub secrets from a HAR document before it is stored.

Header values for cookies and credentials are replaced, cookie values are dropped and
request bodies are removed. Only names, URLs, methods, statuses and timings remain.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from typing import Any

REDACTED = "[redacted]"
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)


def _scrub_headers(headers: Any, names: Collection[str] = (), values: Collection[str] = ()) -> None:
    if not isinstance(headers, list):
        return
    sensitive = SENSITIVE_HEADERS | {n.lower() for n in names}
    for header in headers:
        if not isinstance(header, dict):
            continue
        value = str(header.get("value", ""))
        if str(header.get("name", "")).lower() in sensitive or any(
            secret in value for secret in values
        ):
            header["value"] = REDACTED


def _scrub_cookies(message: dict[str, Any]) -> None:
    cookies = message.get("cookies")
    if isinstance(cookies, list):
        message["cookies"] = [
            {"name": c.get("name", ""), "value": REDACTED} for c in cookies if isinstance(c, dict)
        ]


def scrub_har(
    har: dict[str, Any], *, names: Collection[str] = (), values: Collection[str] = ()
) -> dict[str, Any]:
    """Scrub ``har`` in place and return it.

    ``names`` are extra header names to redact (a target's auth header); any header whose value
    contains one of ``values`` (resolved secrets) is redacted too.
    """
    entries = har.get("log", {}).get("entries", [])
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        for role in ("request", "response"):
            message = entry.get(role)
            if not isinstance(message, dict):
                continue
            _scrub_headers(message.get("headers"), names, values)
            _scrub_cookies(message)
        request = entry.get("request")
        if isinstance(request, dict) and "postData" in request:
            post = request["postData"]
            mime = post.get("mimeType", "") if isinstance(post, dict) else ""
            request["postData"] = {"mimeType": mime, "text": REDACTED}
        response = entry.get("response")
        if isinstance(response, dict) and isinstance(response.get("content"), dict):
            response["content"].pop("text", None)
    return har


def scrub_har_bytes(
    data: bytes, *, names: Collection[str] = (), values: Collection[str] = ()
) -> bytes:
    har = json.loads(data.decode("utf-8"))
    scrubbed = scrub_har(har, names=names, values=values)
    return json.dumps(scrubbed, indent=1, sort_keys=True).encode("utf-8")
