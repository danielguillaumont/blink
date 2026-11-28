"""TLS certificate identity via a separate ``ssl`` handshake (not through the browser)."""

from __future__ import annotations

import hashlib
import socket
import ssl

from cryptography import x509

from .models import TlsInfo


def _peer_certificate(host: str, port: int, timeout: float) -> bytes:
    # Verification is disabled only to *read* the certificate so that an untrusted or
    # expired certificate can still be recorded; trust is evaluated separately below.
    context = ssl.create_default_context()
    context.check_hostname = False
    # Inspection only: no application data is sent over this connection.
    context.verify_mode = ssl.CERT_NONE  # nosec B501
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("server sent no certificate")
    return der


def _is_trusted(host: str, port: int, timeout: float, cafile: str | None) -> bool:
    context = ssl.create_default_context(cafile=cafile)
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host),
        ):
            return True
    except (ssl.SSLError, OSError):
        return False


def inspect_tls(
    host: str, port: int = 443, *, timeout: float = 10.0, cafile: str | None = None
) -> TlsInfo:
    """Return certificate identity for ``host:port``; failures are reported in ``error``."""
    try:
        der = _peer_certificate(host, port, timeout)
    except (OSError, ssl.SSLError) as exc:
        return TlsInfo(host=host, port=port, error=f"{type(exc).__name__}: {exc}")
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = tuple(sorted(san_ext.value.get_values_for_type(x509.DNSName)))
    except x509.ExtensionNotFound:
        san = ()
    return TlsInfo(
        host=host,
        port=port,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        san=san,
        trusted=_is_trusted(host, port, timeout, cafile),
    )
