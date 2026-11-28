"""Per-target proxy and auth for captures.

Secrets are read from environment variables at capture time and are never written to a
snapshot: the header names and values used here are added to the HAR scrubber, and auth is
only ever sent to the target's own origin (a third-party script host never sees it).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..config import BasicAuth, HeaderAuth, ProxyConfig, TargetConfig
from ..errors import ConfigError


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    default = {"http": 80, "https": 443}.get(parts.scheme)
    port = parts.port if parts.port not in (None, default) else None
    host = parts.hostname or ""
    return f"{parts.scheme}://{host}{f':{port}' if port else ''}"


def _env(environ: Mapping[str, str], name: str, target: str, what: str) -> str:
    value = environ.get(name, "")
    if not value:
        raise ConfigError(
            f"target '{target}' needs {what} from environment variable {name}, which is not set",
            hint=f"export {name}=... (from your secret store) before running Blink",
        )
    return value


def proxy_options(proxy: ProxyConfig, environ: Mapping[str, str], target: str) -> dict[str, str]:
    options = {"server": proxy.server}
    if proxy.bypass:
        options["bypass"] = proxy.bypass
    if proxy.username_env and proxy.password_env:
        options["username"] = _env(environ, proxy.username_env, target, "a proxy username")
        options["password"] = _env(environ, proxy.password_env, target, "a proxy password")
    return options


@dataclass(frozen=True)
class Access:
    """Resolved context options plus what must be scrubbed from stored evidence."""

    context_options: dict[str, Any] = field(default_factory=dict)
    origin: str = ""
    header: tuple[str, str] | None = None
    secret_headers: frozenset[str] = frozenset()
    secret_values: frozenset[str] = frozenset()

    def same_origin(self) -> Callable[[str], bool]:
        return lambda url: origin_of(url) == self.origin


def resolve_access(
    target: TargetConfig,
    *,
    profile_proxy: ProxyConfig | None = None,
    environ: Mapping[str, str] | None = None,
) -> Access:
    """Context options for ``target``. A profile proxy wins over the target proxy."""
    env = os.environ if environ is None else environ
    options: dict[str, Any] = {}
    secrets: set[str] = set()
    names: set[str] = set()
    proxy = profile_proxy or target.proxy
    if proxy is not None:
        resolved = proxy_options(proxy, env, target.name)
        options["proxy"] = resolved
        if "password" in resolved:
            secrets.add(resolved["password"])
    origin = origin_of(target.url)
    header: tuple[str, str] | None = None
    auth = target.auth
    if isinstance(auth, BasicAuth):
        password = _env(env, auth.password_env, target.name, "a basic-auth password")
        options["http_credentials"] = {
            "username": _env(env, auth.username_env, target.name, "a basic-auth username"),
            "password": password,
            "origin": origin,
        }
        secrets.add(password)
        names.add("authorization")
    elif isinstance(auth, HeaderAuth):
        value = auth.prefix + _env(env, auth.value_env, target.name, f"the {auth.header} value")
        header = (auth.header, value)
        secrets.update({value, value[len(auth.prefix) :]})
        names.add(auth.header.lower())
    return Access(
        context_options=options,
        origin=origin,
        header=header,
        secret_headers=frozenset(names),
        secret_values=frozenset(s for s in secrets if s),
    )


def install_header(context: Any, access: Access) -> None:
    """Add the auth header to same-origin requests only (never to third parties)."""
    if access.header is None:
        return
    name, value = access.header

    def handler(route: Any) -> None:
        headers = {**route.request.headers, name.lower(): value}
        route.continue_(headers=headers)

    context.route(access.same_origin(), handler)
