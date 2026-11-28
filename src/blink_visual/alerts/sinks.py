"""Alert sinks: webhook (generic, Slack, Teams), SMTP, syslog CEF and a JSONL file.

Sinks use only the standard library (``urllib``, ``smtplib``, ``socket``). Secrets (webhook
URLs, SMTP credentials) come from environment variables named in ``blink.yaml`` and are never
logged, stored in notifications or written to the dead-letter file.
"""

from __future__ import annotations

import json
import os
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from ..config import JsonlSink, SinkConfig, SmtpSink, SyslogSink, WebhookSink
from ..errors import ConfigError
from . import Notification

CEF_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
SEVERITY_EMOJI = {
    "info": "",
    "low": "",
    "medium": ":warning:",
    "high": ":rotating_light:",
    "critical": ":rotating_light:",
}


class DeliveryError(Exception):
    """A sink could not deliver; retried, then dead-lettered."""


class Sink(Protocol):
    name: str

    def send(self, notification: Notification) -> None: ...


def summary_line(n: Notification) -> str:
    a = n.alert
    verb = {"opened": "New", "reopened": "Reopened", "escalated": "Escalated"}.get(n.event, "")
    return f"[{a.severity.label.upper()}] {verb} Blink alert on {a.target} [{a.profile}]: {a.title}"


# -- webhook ----------------------------------------------------------------------------
def slack_payload(n: Notification) -> dict[str, Any]:
    a = n.alert
    return {
        "text": summary_line(n),
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": summary_line(n)[:150], "emoji": True},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why it matters:* {a.why}"}},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"`{a.detector}.{a.change_type}` · alert `{a.id}` · "
                        f"run `{n.run_id}` · seen {a.occurrences}×",
                    }
                ],
            },
        ],
    }


def teams_payload(n: Notification) -> dict[str, Any]:
    """An Adaptive Card message, accepted by Teams Workflows (Power Automate) webhooks."""
    a = n.alert
    color = "Attention" if a.severity.label in ("high", "critical") else "Warning"
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {
                "type": "TextBlock",
                "text": summary_line(n),
                "weight": "Bolder",
                "wrap": True,
                "color": color,
            },
            {"type": "TextBlock", "text": a.why, "wrap": True},
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Detector", "value": f"{a.detector}.{a.change_type}"},
                    {"title": "Alert", "value": a.id},
                    {"title": "Run", "value": n.run_id},
                    {"title": "Occurrences", "value": str(a.occurrences)},
                ],
            },
        ],
    }
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
        ],
    }


def _env(name: str, what: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"environment variable {name} ({what}) is not set")
    return value


class WebhookSender:
    def __init__(self, config: WebhookSink) -> None:
        self.config = config
        self.name = config.name

    def url(self) -> str:
        url = self.config.url or _env(self.config.url_env or "", f"URL for sink {self.name}")
        if not url.startswith(("https://", "http://")):
            raise ConfigError(f"sink {self.name}: webhook URL must be http(s)")
        return url

    def payload(self, n: Notification) -> dict[str, Any]:
        if self.config.format == "slack":
            return slack_payload(n)
        if self.config.format == "teams":
            return teams_payload(n)
        return n.to_dict()

    def send(self, notification: Notification) -> None:
        body = json.dumps(self.payload(notification)).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - scheme checked in url()
            self.url(),
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "blink-alerts/2"},
        )
        try:
            # The scheme is restricted to http(s) in url().
            with urllib.request.urlopen(  # noqa: S310  # nosec B310
                request, timeout=self.config.timeout_s
            ) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            raise DeliveryError(f"HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise DeliveryError(f"connection failed: {reason}") from None
        if not 200 <= status < 300:
            raise DeliveryError(f"HTTP {status}")


# -- SMTP ---------------------------------------------------------------------------------
class SmtpSender:
    def __init__(self, config: SmtpSink) -> None:
        self.config = config
        self.name = config.name

    def message(self, n: Notification) -> EmailMessage:
        a = n.alert
        msg = EmailMessage()
        msg["Subject"] = summary_line(n)[:200]
        msg["From"] = self.config.from_addr
        msg["To"] = ", ".join(self.config.to)
        lines = [
            summary_line(n),
            "",
            f"Why it matters: {a.why}",
            "",
            f"Detector:    {a.detector}.{a.change_type}",
            f"Subject:     {a.subject}",
            f"Alert:       {a.id} ({a.state}, seen {a.occurrences}x)",
            f"Run:         {n.run_id}",
            f"First seen:  {a.first_seen_at}",
            "",
            "Acknowledge with: blink alerts ack " + a.id + ' --by "your name"',
        ]
        msg.set_content("\n".join(lines))
        return msg

    def send(self, notification: Notification) -> None:
        c = self.config
        try:
            if c.ssl:
                client: smtplib.SMTP = smtplib.SMTP_SSL(
                    c.host, c.port, timeout=c.timeout_s, context=ssl.create_default_context()
                )
            else:
                client = smtplib.SMTP(c.host, c.port, timeout=c.timeout_s)
            with client:
                client.ehlo()
                if c.starttls and not c.ssl:
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                if c.username_env:
                    password = _env(c.password_env or "", f"SMTP password for sink {self.name}")
                    client.login(_env(c.username_env, f"SMTP user for {self.name}"), password)
                client.send_message(self.message(notification))
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(f"SMTP failed: {type(exc).__name__}: {exc}") from None


# -- syslog CEF -----------------------------------------------------------------------------
def _cef_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _cef_ext(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "").replace("\n", "\\n")


def cef_message(n: Notification, *, version: str) -> str:
    a = n.alert
    ext = {
        "rt": str(int(datetime.now(UTC).timestamp() * 1000)),
        "act": n.event,
        "cs1Label": "target",
        "cs1": a.target,
        "cs2Label": "profile",
        "cs2": a.profile,
        "cs3Label": "alertId",
        "cs3": a.id,
        "cs4Label": "runId",
        "cs4": n.run_id,
        "cs5Label": "why",
        "cs5": a.why[:1000],
        "cs6Label": "subject",
        "cs6": a.subject[:500],
        "cnt": str(a.occurrences),
        "outcome": a.state,
    }
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items())
    header = "|".join(
        _cef_header(v)
        for v in (
            "CEF:0",
            "Blink",
            "Blink",
            version,
            f"{a.detector}.{a.change_type}",
            a.title[:256],
            str(CEF_SEVERITY[a.severity.label]),
        )
    )
    return f"{header}|{extension}"


def syslog_line(n: Notification, *, facility: int, version: str, hostname: str) -> bytes:
    """RFC 5424 with a CEF message. Severity: critical→2, high→3, medium→4, else 6."""
    level = {"critical": 2, "high": 3, "medium": 4}.get(n.alert.severity.label, 6)
    stamp = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    pri = facility * 8 + level
    return f"<{pri}>1 {stamp} {hostname} blink - - - {cef_message(n, version=version)}".encode()


class SyslogSender:
    def __init__(self, config: SyslogSink, *, version: str) -> None:
        self.config = config
        self.name = config.name
        self.version = version

    def send(self, notification: Notification) -> None:
        c = self.config
        line = syslog_line(
            notification, facility=c.facility, version=self.version, hostname=socket.gethostname()
        )
        try:
            if c.protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(c.timeout_s)
                    sock.sendto(line, (c.host, c.port))
            else:
                with socket.create_connection((c.host, c.port), timeout=c.timeout_s) as sock:
                    sock.sendall(line + b"\n")
        except OSError as exc:
            raise DeliveryError(f"syslog failed: {exc}") from None


# -- JSONL ------------------------------------------------------------------------------------
class JsonlSender:
    def __init__(self, config: JsonlSink, *, base: Path) -> None:
        self.config = config
        self.name = config.name
        path = Path(config.path)
        self.path = path if path.is_absolute() else base / path

    def send(self, notification: Notification) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(notification.to_dict(), sort_keys=True) + "\n")
        except OSError as exc:
            raise DeliveryError(f"cannot write {self.path}: {exc.strerror or exc}") from None


def build_sink(config: SinkConfig, *, base: Path, version: str) -> Sink:
    if isinstance(config, WebhookSink):
        return WebhookSender(config)
    if isinstance(config, SmtpSink):
        return SmtpSender(config)
    if isinstance(config, SyslogSink):
        return SyslogSender(config, version=version)
    return JsonlSender(config, base=base)
