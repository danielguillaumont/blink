"""Alert state machine, sink contracts (local fake servers) and delivery retry/dead-letter."""

from __future__ import annotations

import json
import socket
import socketserver
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import pairwise
from typing import ClassVar

import pytest
from helpers import snapshot

from blink_visual.alerts import (
    ACCEPTED,
    ACKNOWLEDGED,
    OPEN,
    RESOLVED,
    AlertManager,
    Notification,
)
from blink_visual.alerts.delivery import Dispatcher
from blink_visual.alerts.sinks import (
    DeliveryError,
    JsonlSender,
    SmtpSender,
    SyslogSender,
    WebhookSender,
    cef_message,
    slack_payload,
    teams_payload,
)
from blink_visual.config import AlertsConfig, JsonlSink, SmtpSink, SyslogSink, WebhookSink
from blink_visual.errors import BlinkError
from blink_visual.findings import Finding, Severity
from blink_visual.store import Store


def finding(severity: Severity = Severity.HIGH, subject: str = "https://cdn.example/x.js"):
    return Finding(
        detector="scripts",
        change_type="added",
        subject=subject,
        title=f"New third-party script: {subject}",
        target="checkout",
        profile="desktop-chrome",
        severity=severity,
        why="A new | script = risk\nsecond line",
        rule_id="scripts.added",
    )


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / ".blink") as opened:
        yield opened


@pytest.fixture
def manager(store):
    return AlertManager(store)


# --- state machine -------------------------------------------------------------------


def test_new_finding_opens_an_alert_and_repeats_are_deduplicated(manager, store):
    (n,) = manager.ingest("run-1", [finding()], at="2026-11-27T10:00:00Z")
    assert n.event == "opened"
    assert n.alert.state == OPEN
    assert manager.ingest("run-2", [finding()], at="2026-11-28T10:00:00Z") == []
    alert = manager.get(finding().id)
    assert alert.occurrences == 2
    assert alert.first_run_id == "run-1"
    assert alert.last_run_id == "run-2"
    assert len(manager.all()) == 1
    kinds = [r.kind for r in store.ledger.records()]
    assert kinds == ["alert.opened"]


def test_escalation_notifies_once(manager):
    manager.ingest("run-1", [finding(Severity.MEDIUM)])
    (n,) = manager.ingest("run-2", [finding(Severity.CRITICAL)])
    assert n.event == "escalated"
    assert n.alert.severity == Severity.CRITICAL
    assert manager.ingest("run-3", [finding(Severity.MEDIUM)]) == []
    assert manager.get(finding().id).severity == Severity.CRITICAL


def test_lifecycle_open_ack_resolve_reopen(manager, store):
    manager.ingest("run-1", [finding()])
    alert_id = finding().id
    assert manager.transition(alert_id, ACKNOWLEDGED, actor="alice").state == ACKNOWLEDGED
    with pytest.raises(BlinkError, match="cannot become open"):
        manager.transition(alert_id, OPEN, actor="alice")
    resolved = manager.transition(alert_id, RESOLVED, actor="bob", note="vendor fixed it")
    assert resolved.state == RESOLVED
    assert resolved.updated_by == "bob"
    (n,) = manager.ingest("run-2", [finding()])
    assert n.event == "reopened"
    assert manager.get(alert_id).state == OPEN
    history = [(e["from_state"], e["to_state"], e["actor"]) for e in manager.events(alert_id)]
    assert history == [
        (None, OPEN, "blink"),
        (OPEN, ACKNOWLEDGED, "alice"),
        (ACKNOWLEDGED, RESOLVED, "bob"),
        (RESOLVED, OPEN, "blink"),
    ]
    kinds = [r.kind for r in store.ledger.records()]
    assert kinds == ["alert.opened", "alert.acknowledged", "alert.resolved", "alert.reopened"]
    assert store.ledger.verify().ok


def test_transition_validation(manager):
    manager.ingest("run-1", [finding()])
    alert_id = finding().id
    with pytest.raises(BlinkError, match="unknown alert state"):
        manager.transition(alert_id, "closed", actor="a")
    with pytest.raises(BlinkError, match="actor"):
        manager.transition(alert_id, ACKNOWLEDGED, actor=" ")
    with pytest.raises(BlinkError, match="reason"):
        manager.transition(alert_id, ACCEPTED, actor="a")
    with pytest.raises(BlinkError, match="unknown alert"):
        manager.get("nope")


def test_accepting_a_change_rebaselines_and_records_who_and_why(manager, store):
    base = snapshot(id="snap-1")
    new = snapshot(id="snap-2")
    store.ensure_target(base.target, base.url)
    store.save_snapshot(base)
    store.save_snapshot(new)
    store.set_baseline(base.target, base.profile, base.id)
    with store.db.transaction() as conn:
        conn.execute(
            "INSERT INTO runs (id, kind, started_at, finished_at, status) "
            "VALUES ('run-1', 'scan', 'x', 'x', 'findings')"
        )
        conn.execute(
            "INSERT INTO run_results (run_id, target, profile, status, current_snapshot) "
            "VALUES ('run-1', ?, ?, 'ok', 'snap-2')",
            (base.target, base.profile),
        )
    manager.ingest("run-1", [finding()])
    accepted = manager.transition(
        finding().id, ACCEPTED, actor="carol", note="new chat widget, change ticket 42"
    )
    assert accepted.state == ACCEPTED
    assert store.baseline_id(base.target, base.profile) == "snap-2"
    baseline = store.baselines()[0]
    assert "carol" in baseline["reason"]
    assert "ticket 42" in baseline["reason"]
    record = store.ledger.records({"alert.accepted-change"})[0]
    assert record.payload["actor"] == "carol"
    assert record.payload["note"] == "new chat widget, change ticket 42"


def test_accepting_without_snapshot_fails(manager):
    manager.ingest("run-x", [finding()])
    with pytest.raises(BlinkError, match="no snapshot"):
        manager.transition(finding().id, ACCEPTED, actor="a", note="n")


# --- sink payloads ---------------------------------------------------------------------


@pytest.fixture
def notification(manager):
    (n,) = manager.ingest("run-1", [finding()])
    return n


def test_notification_has_no_secrets_or_evidence(notification):
    data = notification.to_dict()
    assert data["schema"] == "blink.alert.v1"
    assert data["severity"] == "high"
    assert "evidence" not in data
    assert "attributes" not in data


def test_slack_and_teams_formats(notification):
    slack = slack_payload(notification)
    assert slack["text"].startswith("[HIGH] New Blink alert on checkout")
    assert slack["blocks"][0]["type"] == "header"
    teams = teams_payload(notification)
    card = teams["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["content"]["type"] == "AdaptiveCard"
    facts = {f["title"]: f["value"] for f in card["content"]["body"][2]["facts"]}
    assert facts["Alert"] == notification.alert.id


def test_cef_escaping(notification):
    tricky = replace(notification.alert, title="a|b\\c", why="x=y\nz")
    line = cef_message(Notification("opened", tricky, "run-1"), version="2.0.0")
    _header, _, _ext = line.rpartition("|")
    assert line.startswith("CEF:0|Blink|Blink|2.0.0|scripts.added|a\\|b\\\\c|8|")
    assert "cs5=x\\=y\\nz" in line
    assert "\n" not in line


# --- contract tests with local fake servers -------------------------------------------------


class _Recorder(BaseHTTPRequestHandler):
    statuses: ClassVar[list[int]] = []
    bodies: ClassVar[list[dict]] = []

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).bodies.append(
            {"body": json.loads(self.rfile.read(length)), "type": self.headers["Content-Type"]}
        )
        status = type(self).statuses.pop(0) if type(self).statuses else 200
        self.send_response(status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def http_sink():
    handler = type("Handler", (_Recorder,), {"statuses": [], "bodies": []})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield handler, f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("fmt", ["generic", "slack", "teams"])
def test_webhook_contract(http_sink, notification, fmt, monkeypatch):
    handler, url = http_sink
    monkeypatch.setenv("BLINK_TEST_HOOK", url)
    sender = WebhookSender(
        WebhookSink(name="hook", type="webhook", url_env="BLINK_TEST_HOOK", format=fmt)
    )
    sender.send(notification)
    (received,) = handler.bodies
    assert received["type"] == "application/json"
    body = received["body"]
    if fmt == "generic":
        assert body["alert_id"] == notification.alert.id
    elif fmt == "slack":
        assert "blocks" in body
    else:
        assert body["type"] == "message"


def test_webhook_errors(http_sink, notification, monkeypatch):
    handler, url = http_sink
    handler.statuses.append(500)
    sender = WebhookSender(WebhookSink(name="hook", type="webhook", url=url))
    with pytest.raises(DeliveryError, match="HTTP 500"):
        sender.send(notification)
    monkeypatch.delenv("BLINK_MISSING_HOOK", raising=False)
    missing = WebhookSender(WebhookSink(name="h", type="webhook", url_env="BLINK_MISSING_HOOK"))
    with pytest.raises(BlinkError, match="BLINK_MISSING_HOOK"):
        missing.send(notification)
    closed = WebhookSender(
        WebhookSink(name="h", type="webhook", url="http://127.0.0.1:9/x", timeout_s=2)
    )
    with pytest.raises(DeliveryError, match="connection failed"):
        closed.send(notification)


class _FakeSmtp(socketserver.StreamRequestHandler):
    messages: ClassVar[list[dict]] = []

    def handle(self):
        self.wfile.write(b"220 fake ESMTP\r\n")
        envelope = {"rcpt": []}
        while True:
            line = self.rfile.readline().decode().strip()
            if not line:
                return
            verb = line.split()[0].upper()
            if verb in ("EHLO", "HELO"):
                self.wfile.write(b"250-fake\r\n250 OK\r\n")
            elif verb == "MAIL":
                envelope["from"] = line
                self.wfile.write(b"250 OK\r\n")
            elif verb == "RCPT":
                envelope["rcpt"].append(line)
                self.wfile.write(b"250 OK\r\n")
            elif verb == "DATA":
                self.wfile.write(b"354 go\r\n")
                data = []
                while (chunk := self.rfile.readline().decode()) != ".\r\n":
                    data.append(chunk)
                envelope["data"] = "".join(data)
                type(self).messages.append(envelope)
                self.wfile.write(b"250 queued\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"502 no\r\n")


def test_smtp_contract(notification):
    handler = type("Smtp", (_FakeSmtp,), {"messages": []})
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        config = SmtpSink(
            name="mail",
            type="smtp",
            host="127.0.0.1",
            port=server.server_address[1],
            starttls=False,
            **{"from": "blink@example.test"},
            to=["soc@example.test", "web@example.test"],
        )
        SmtpSender(config).send(notification)
    finally:
        server.shutdown()
        server.server_close()
    (message,) = handler.messages
    assert "blink@example.test" in message["from"]
    assert len(message["rcpt"]) == 2
    assert "Subject: [HIGH] New Blink alert on checkout" in message["data"]
    assert "blink alerts ack" in message["data"]


def test_smtp_failure_is_a_delivery_error(notification):
    config = SmtpSink(
        name="mail",
        type="smtp",
        host="127.0.0.1",
        port=9,
        starttls=False,
        timeout_s=2,
        **{"from": "a@example.test"},
        to=["b@example.test"],
    )
    with pytest.raises(DeliveryError, match="SMTP failed"):
        SmtpSender(config).send(notification)


def test_syslog_udp_contract(notification):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(5)
        port = server.getsockname()[1]
        SyslogSender(SyslogSink(name="soc", type="syslog", port=port), version="2.0.0").send(
            notification
        )
        data, _ = server.recvfrom(65535)
    line = data.decode()
    assert line.startswith("<107>1 ")  # facility 13 (audit) * 8 + severity 3 (error) for high
    assert " blink - - - CEF:0|Blink|Blink|2.0.0|scripts.added|" in line
    assert f"cs3={notification.alert.id}" in line


def test_syslog_tcp_contract(notification):
    received: list[bytes] = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            received.append(self.rfile.readline())

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    config = SyslogSink(name="soc", type="syslog", port=server.server_address[1], protocol="tcp")
    SyslogSender(config, version="2.0.0").send(notification)
    thread.join(5)
    server.server_close()
    assert received[0].endswith(b"\n")
    assert b"CEF:0|Blink" in received[0]
    with pytest.raises(DeliveryError, match="syslog failed"):
        SyslogSender(
            SyslogSink(name="x", type="syslog", port=9, protocol="tcp", timeout_s=2),
            version="2",
        ).send(notification)


def test_jsonl_contract(tmp_path, notification):
    sender = JsonlSender(
        JsonlSink(name="file", type="jsonl", path="out/alerts.jsonl"), base=tmp_path
    )
    sender.send(notification)
    sender.send(notification)
    lines = (tmp_path / "out" / "alerts.jsonl").read_text("utf-8").splitlines()
    assert [json.loads(x)["alert_id"] for x in lines] == [notification.alert.id] * 2


# --- delivery: retry and dead-letter -----------------------------------------------------------


class Flaky:
    def __init__(self, failures: int) -> None:
        self.name = "flaky"
        self.failures = failures
        self.calls = 0

    def send(self, notification) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise DeliveryError(f"boom {self.calls}")


def _dispatcher(store, sink, **config):
    sleeps: list[float] = []
    cfg = AlertsConfig(**{"retries": 3, "backoff": "1s", **config})
    sink_config = JsonlSink(name=sink.name, type="jsonl", path="unused")
    return Dispatcher(store, cfg, [(sink_config, sink)], sleep=sleeps.append), sleeps


def test_delivery_retries_with_exponential_backoff(store, notification):
    sink = Flaky(failures=2)
    dispatcher, sleeps = _dispatcher(store, sink)
    (result,) = dispatcher.dispatch([notification])
    assert result.delivered
    assert result.attempts == 3
    assert sleeps == [1.0, 2.0]
    assert not dispatcher.dead_letter_path.exists()


def test_undeliverable_notification_is_dead_lettered(store, notification):
    sink = Flaky(failures=99)
    dispatcher, sleeps = _dispatcher(store, sink)
    (result,) = dispatcher.dispatch([notification])
    assert not result.delivered
    assert result.attempts == 4
    assert sleeps == [1.0, 2.0, 4.0]
    (line,) = dispatcher.dead_letter_path.read_text("utf-8").splitlines()
    record = json.loads(line)
    assert record["sink"] == "flaky"
    assert record["error"] == "boom 4"
    assert record["notification"]["alert_id"] == notification.alert.id
    (ledgered,) = store.ledger.records({"alert.dead_letter"})
    assert ledgered.payload["attempts"] == 4
    assert all(b > a for a, b in pairwise(sleeps))


def test_severity_routing(store, manager):
    (low,) = manager.ingest("run-1", [finding(Severity.LOW, subject="a")])
    (high,) = manager.ingest("run-1", [finding(Severity.HIGH, subject="b")])
    sink = Flaky(failures=0)
    dispatcher, _ = _dispatcher(store, sink)  # default min_severity: high
    results = dispatcher.dispatch([low, high])
    assert [r.alert_id for r in results] == [high.alert.id]
    everything = Flaky(failures=0)
    cfg = AlertsConfig(min_severity="high")
    per_sink = JsonlSink(name="all", type="jsonl", path="x", min_severity="info")
    both = Dispatcher(store, cfg, [(per_sink, everything)], sleep=lambda _: None)
    assert len(both.dispatch([low, high])) == 2
