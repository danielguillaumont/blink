"""Run the dashboard with uvicorn, in the foreground (CLI) or a background thread (tests)."""

from __future__ import annotations

import socket
import threading
import time
from types import TracebackType

import uvicorn

from ..errors import BlinkError
from ..project import Project
from . import create_app
from .security import is_loopback, load_token

DEFAULT_PORT = 8765


class DashboardServer:
    def __init__(self, project: Project, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.loopback = is_loopback(host)
        token = load_token(project.store_dir)
        self.app = create_app(project, token=token, loopback=self.loopback)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._socket = socket.socket(family, socket.SOCK_STREAM)
        try:
            self._socket.bind((host, port))
        except OSError as exc:
            self._socket.close()
            raise BlinkError(
                f"cannot bind the dashboard to {host}:{port}: {exc.strerror or exc}",
                hint="use --port to pick another port",
            ) from None
        self._socket.listen(128)
        self.port = int(self._socket.getsockname()[1])
        self._server = uvicorn.Server(
            uvicorn.Config(
                self.app,
                log_level="warning",
                access_log=False,
                lifespan="off",
                server_header=False,
                proxy_headers=False,
            )
        )
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    def start(self, timeout: float = 10.0) -> DashboardServer:
        self._thread = threading.Thread(
            target=self._server.run,
            kwargs={"sockets": [self._socket]},
            daemon=True,
            name="blink-serve",
        )
        self._thread.start()
        deadline = time.monotonic() + timeout
        while not self._server.started:
            if time.monotonic() > deadline:
                self.stop()
                raise BlinkError("the dashboard did not start in time")
            time.sleep(0.02)
        return self

    def serve_forever(self) -> None:
        try:
            self._server.run(sockets=[self._socket])
        finally:
            self._socket.close()

    def stop(self) -> None:
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._socket.close()

    def __enter__(self) -> DashboardServer:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()
