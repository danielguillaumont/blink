"""Run the three lab apps on loopback ports, in-process (tests) or in the foreground (CLI)."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from types import TracebackType

import uvicorn

from ..errors import BlinkError
from .app import LabState, build_cdn, build_shop, build_sink
from .scenarios import DEFAULT_SCENARIO, SCENARIOS

DEFAULT_PORTS = (8780, 8781, 8782)


def _require_loopback(host: str) -> None:
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise BlinkError(
            f"the lab only binds to loopback addresses, not {host!r}",
            hint="use 127.0.0.1; the lab must never be exposed to a network",
        )


def _bind(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError as exc:
        sock.close()
        raise BlinkError(
            f"cannot bind the lab to {host}:{port}: {exc.strerror or exc}",
            hint="is another lab already running? use --port to pick other ports",
        ) from None
    sock.listen(128)
    return sock


class Lab:
    """Shop, CDN and sink servers. Ports of 0 pick free ephemeral ports."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        ports: tuple[int, int, int] = (0, 0, 0),
        scenario: str = DEFAULT_SCENARIO,
    ) -> None:
        _require_loopback(host)
        if scenario not in SCENARIOS:
            raise BlinkError(f"unknown scenario '{scenario}' (known: {', '.join(SCENARIOS)})")
        self.host = host
        self._sockets = [_bind(host, port) for port in ports]
        self.ports = tuple(int(s.getsockname()[1]) for s in self._sockets)
        url_host = f"[{host}]" if ":" in host else host
        shop, cdn, sink = (f"http://{url_host}:{p}" for p in self.ports)
        self.state = LabState(shop_origin=shop, cdn_origin=cdn, sink_origin=sink, scenario=scenario)
        apps = (build_shop(self.state), build_cdn(self.state), build_sink(self.state))
        self._servers = [
            uvicorn.Server(
                uvicorn.Config(app, log_level="warning", access_log=False, lifespan="off")
            )
            for app in apps
        ]
        self._threads: list[threading.Thread] = []

    @property
    def shop_origin(self) -> str:
        return self.state.shop_origin

    @property
    def checkout_url(self) -> str:
        return f"{self.state.shop_origin}/checkout"

    def set_scenario(self, name: str) -> None:
        self.state.set_scenario(name)

    def start(self, timeout: float = 10.0) -> Lab:
        for server, sock in zip(self._servers, self._sockets, strict=True):
            thread = threading.Thread(
                target=server.run, kwargs={"sockets": [sock]}, daemon=True, name="blink-lab"
            )
            thread.start()
            self._threads.append(thread)
        deadline = time.monotonic() + timeout
        while not all(s.started for s in self._servers):
            if time.monotonic() > deadline:
                self.stop()
                raise BlinkError("the lab servers did not start in time")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        for server in self._servers:
            server.should_exit = True
        for thread in self._threads:
            thread.join(timeout=10)
        for sock in self._sockets:
            sock.close()
        self._threads.clear()

    def wait(self) -> None:
        """Block until interrupted (Ctrl+C)."""
        try:
            while any(t.is_alive() for t in self._threads):
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def __enter__(self) -> Lab:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()
