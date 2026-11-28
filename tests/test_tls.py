"""TLS identity via a local self-signed server on 127.0.0.1 (no external network)."""

import datetime as dt
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from blink_visual.capture.tls import inspect_tls


def self_signed(tmp_path: Path) -> tuple[Path, Path, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "blink-test.local")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(4242)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("blink-test.local")]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_path, key_path, fingerprint


@pytest.fixture
def tls_server(tmp_path):
    cert, key, fingerprint = self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port, fingerprint, cert
    stop.set()
    thread.join(2)
    listener.close()


@pytest.mark.integration
def test_inspect_self_signed_certificate(tls_server):
    port, fingerprint, _ = tls_server
    info = inspect_tls("127.0.0.1", port, timeout=5)
    assert info.error is None
    assert info.fingerprint_sha256 == fingerprint
    assert info.subject == "CN=blink-test.local"
    assert info.issuer == info.subject
    assert info.serial == format(4242, "x")
    assert info.san == ("blink-test.local",)
    assert info.trusted is False
    assert info.not_after is not None


@pytest.mark.integration
def test_unreachable_tls_reports_an_error():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    info = inspect_tls("127.0.0.1", port, timeout=2)
    assert info.error is not None
    assert info.fingerprint_sha256 is None
