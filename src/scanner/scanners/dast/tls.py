"""TLS / certificate inspection (``dast.tls.*``).

Two halves, kept apart so the logic is testable without a live server:

- ``analyze_tls`` — pure: given a parsed certificate, the negotiated protocol,
  and the current time, decide what is wrong (expired, expiring soon, weak
  protocol, self-signed). All the real judgement lives here.
- ``fetch_tls`` — thin I/O: open a TLS socket *without verification* (so we can
  still read an expired or self-signed cert), grab the peer certificate and the
  negotiated protocol version. Runs in a worker thread; exercised end-to-end.

This module holds the **only** socket in the tool that does not go through
:class:`~scanner.core.http.AsyncHttpClient`, because a certificate has to be read
from a raw handshake that httpx will not expose. Being the only exception makes it
the only place the scope boundary can be missed, so ``fetch_tls`` takes the
:class:`~scanner.core.gate.RequestGate` as a *required* argument and authorizes
through it before connecting (contract §9).
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509

from scanner.core.context import why_exception
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.gate import OutOfScopeError, RequestClass, RequestGate
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


async def fetch_tls(
    url: str, gate: RequestGate, *, timeout: float = 15.0
) -> tuple[tuple[x509.Certificate, str | None] | None, str | None]:
    """Return ``((certificate, protocol), None)``, or ``(None, reason)`` if the
    handshake could not be made.

    **Two return values, because there is no certificate that means "we could not
    read one".** This used to return ``None`` on any failure, and the caller turned
    that into an empty finding list — so a host whose handshake timed out produced
    exactly the output of a host with a flawless certificate: no findings, no
    error, nothing said (D70). ``reason`` is a sentence naming what went wrong, for
    the caller to put on the report.

    ``gate`` is required, and required *positionally*, because this function
    bypasses the HTTP choke point and therefore has to re-apply the same scope
    decision itself. Making it optional would leave the guarantee resting on every
    future caller remembering to pass it — the failure mode decisions.md D44 is
    about — so omitting it is a ``TypeError`` rather than a silently ungated probe.

    **Stricter than an ordinary request.** Only a *target* host qualifies. The gate
    would also authorize an infrastructure host such as ``api.anthropic.com``,
    since ordinary passive traffic there is how the AI advisor works — but §9
    permits this raw-socket path "only to a host already in Scope", and the tool
    has no business handshaking with its own providers.

    **A refusal raises; an unreachable host comes back as a reason.** The asymmetry
    is deliberate. A scope refusal means the scanner tried to touch something it was
    not authorized to touch, which is *our* bug: it must not be absorbed by the same
    ``except`` that catches connection failures, and it reaches the report as an
    exception through ``ctx.run_check``. A failed handshake is the target's business
    and produces no findings — but "no findings" is a claim about the certificate,
    and we do not have one to make it about, so it is reported too.

    The blocking socket work runs in a worker thread so it never stalls the event
    loop. Only ``https`` URLs are probed; the caller filters the rest out first and
    has a better sentence for them, so the reason given here is a backstop.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        # Nothing will be reached, so there is nothing to authorize.
        return None, f"{url!r} is not an https URL with a host, so there is no handshake"
    if gate.authorize(url) is not RequestClass.TARGET:
        raise OutOfScopeError(
            f"Refusing a raw TLS handshake with {url!r}: the certificate probe is "
            "permitted only against an in-scope target host, never against the "
            "tool's own infrastructure."
        )
    port = parts.port or 443
    try:
        result = await asyncio.to_thread(_fetch_blocking, parts.hostname, port, timeout)
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        return None, (
            f"the TLS handshake with {parts.hostname}:{port} did not complete, so no "
            f"certificate was read: {why_exception(exc)}"
        )
    return result, None


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
