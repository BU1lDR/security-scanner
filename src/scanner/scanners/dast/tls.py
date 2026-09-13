"""TLS / certificate inspection (``dast.tls.*``).

Two halves, kept apart so the logic is testable without a live server:

- ``analyze_tls`` — pure: given a parsed certificate, the negotiated protocol,
  and the current time, decide what is wrong (expired, expiring soon, weak
  protocol, self-signed). All the real judgement lives here.
- ``fetch_tls`` — thin I/O: open a TLS socket *without verification* (so we can
  still read an expired or self-signed cert), grab the peer certificate and the
  negotiated protocol version. Runs in a worker thread; exercised end-to-end.
"""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_EXPIRY_WARN = timedelta(days=14)
_REF = ["https://owasp.org/www-project-web-security-testing-guide/", "CWE-295"]


def _finding(url: str, rule_id: str, title: str, severity: Severity,
             evidence: str, remediation: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        location=Location.for_url(url, method="GET"),
        evidence=evidence,
        remediation=remediation,
        scanner="dast",
        references=list(_REF),
        fix=None,
    )


def analyze_tls(url: str, cert: x509.Certificate, protocol: str | None,
                now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if not_after < now:
        findings.append(_finding(
            url, "dast.tls.expired-cert", "TLS certificate has expired",
            Severity.HIGH,
            f"Certificate expired on {not_after.isoformat()}.",
            "Renew the TLS certificate; browsers reject expired certificates.",
        ))
    elif not_after < now + _EXPIRY_WARN:
        findings.append(_finding(
            url, "dast.tls.expiring-soon", "TLS certificate expires soon",
            Severity.LOW,
            f"Certificate expires on {not_after.isoformat()}.",
            "Renew the TLS certificate before it expires to avoid an outage.",
        ))

    if not_before > now:
        findings.append(_finding(
            url, "dast.tls.not-yet-valid", "TLS certificate is not yet valid",
            Severity.MEDIUM,
            f"Certificate is not valid until {not_before.isoformat()}.",
            "Install a certificate whose validity period has already started.",
        ))

    if protocol in _WEAK_PROTOCOLS:
        findings.append(_finding(
            url, "dast.tls.weak-protocol",
            f"Server negotiated a weak TLS protocol ({protocol})",
            Severity.MEDIUM,
            f"The connection was established over {protocol}.",
            "Disable SSLv3/TLSv1.0/TLSv1.1; require TLSv1.2 or newer.",
        ))

    if cert.issuer == cert.subject:
        findings.append(_finding(
            url, "dast.tls.self-signed", "TLS certificate is self-signed",
            Severity.MEDIUM,
            "The certificate's issuer and subject are identical (self-signed).",
            "Use a certificate signed by a trusted CA so clients can verify it.",
        ))

    return findings


def _fetch_blocking(host: str, port: int, timeout: float) -> tuple[x509.Certificate, str | None]:
    ctx = ssl.create_default_context()
    # We must read the cert even when it is invalid, so verification is disabled
    # here; the analysis (expiry/self-signed/etc.) is done by us, not the stack.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ssl.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            protocol = tls.version()
    return x509.load_der_x509_certificate(der), protocol


async def fetch_tls(url: str, *, timeout: float = 15.0):
    """Return ``(certificate, protocol)`` for ``url`` or ``None`` if unreachable.

    The blocking socket work runs in a worker thread so it never stalls the event
    loop. Only ``https`` URLs are probed.
    """
    import asyncio

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    port = parts.port or 443
    try:
        return await asyncio.to_thread(_fetch_blocking, parts.hostname, port, timeout)
    except Exception:  # noqa: BLE001 - unreachable/handshake failure is not our finding
        return None


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
