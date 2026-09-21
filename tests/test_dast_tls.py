import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanner.core.egress import Egress
from scanner.core.finding import Severity
from scanner.core.gate import OutOfScopeError, RequestGate
from scanner.core.location import LocationKind
from scanner.core.rule_id import is_valid
from scanner.core.scope import Scope
from scanner.scanners.dast import tls as tls_module
from scanner.scanners.dast.tls import analyze_tls, fetch_tls

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _cert(not_before, not_after, cn="example.com", issuer_cn="Test CA"):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(_KEY, hashes.SHA256())
    )


def _ids(findings):
    return {f.rule_id for f in findings}


def test_healthy_cert_and_modern_protocol_has_no_findings():
    cert = _cert(_NOW - timedelta(days=10), _NOW + timedelta(days=300))
    assert analyze_tls("https://example.com/", cert, "TLSv1.3", _NOW) == []


def test_expired_certificate_is_high():
    cert = _cert(_NOW - timedelta(days=400), _NOW - timedelta(days=1))
    findings = {f.rule_id: f for f in analyze_tls("https://example.com/", cert, "TLSv1.3", _NOW)}
    assert "dast.tls.expired-cert" in findings
    f = findings["dast.tls.expired-cert"]
    assert is_valid(f.rule_id)
    assert f.severity is Severity.HIGH
    assert f.scanner == "dast"
    assert f.location.kind is LocationKind.URL
    assert f.fix is None


def test_certificate_expiring_soon_is_low():
    cert = _cert(_NOW - timedelta(days=10), _NOW + timedelta(days=3))
    ids = _ids(analyze_tls("https://example.com/", cert, "TLSv1.3", _NOW))
    assert "dast.tls.expiring-soon" in ids
    assert "dast.tls.expired-cert" not in ids


def test_weak_protocol_is_flagged():
    cert = _cert(_NOW - timedelta(days=10), _NOW + timedelta(days=300))
    ids = _ids(analyze_tls("https://example.com/", cert, "TLSv1", _NOW))
    assert "dast.tls.weak-protocol" in ids


def test_self_signed_certificate_is_flagged():
    cert = _cert(_NOW - timedelta(days=10), _NOW + timedelta(days=300),
                 cn="example.com", issuer_cn="example.com")
    ids = _ids(analyze_tls("https://example.com/", cert, "TLSv1.3", _NOW))
    assert "dast.tls.self-signed" in ids


# --- the raw-socket path is gated too (contract §9) --------------------------
#
# fetch_tls is the one place in the tool that opens a socket without going
# through AsyncHttpClient, so it is the one place the scope check can be missed.
# It was: the probe took a URL and a timeout and nothing else, while
# core/http.py claimed it "reuses self.gate to apply the same scope check".


def _gate(*hosts):
    return RequestGate(Scope(allowed_hosts=set(hosts)), Egress())


def _tripwire(*args, **kwargs):
    raise AssertionError("a TLS socket was opened without authorization")


def test_fetch_tls_cannot_be_called_without_a_gate():
    """The gate is required *positionally*, so forgetting it is a TypeError.

    An optional gate would be no guarantee at all: the next caller reintroduces
    the ungated socket by omission, and the omission looks like ordinary code.
    """
    with pytest.raises(TypeError):
        fetch_tls("https://example.com/")


def test_an_out_of_scope_host_is_refused_before_any_socket_is_opened(monkeypatch):
    monkeypatch.setattr(tls_module, "_fetch_blocking", _tripwire)
    with pytest.raises(OutOfScopeError):
        asyncio.run(fetch_tls("https://not-the-target.example/", _gate("target.example")))


def test_an_egress_host_is_refused_even_though_an_http_request_there_is_allowed(monkeypatch):
    """Stricter than the ordinary passive rule, on purpose.

    ``gate.authorize`` *permits* api.anthropic.com — passive traffic to tool
    infrastructure is how the AI advisor works. But §9 allows this raw-socket
    path "only to a host already in Scope", and the tool has no business
    handshaking with its own providers, so EGRESS is not good enough here.
    """
    monkeypatch.setattr(tls_module, "_fetch_blocking", _tripwire)
    gate = _gate("target.example")
    assert gate.egress.allows("https://api.anthropic.com/") is True  # http would allow it
    with pytest.raises(OutOfScopeError):
        asyncio.run(fetch_tls("https://api.anthropic.com/", gate))


def test_an_unreachable_in_scope_host_comes_back_with_a_reason(monkeypatch):
    """The deliberate asymmetry, corrected: unauthorized raises, unreachable
    reports. It used to return a bare ``None``, and the name of this test was
    ``..._is_still_a_quiet_none`` — quiet was the bug (D70). A scope refusal is
    *our* error and still must not be absorbed by the same ``except Exception``
    that catches connection failures, which is what the test below checks.
    """
    def _boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(tls_module, "_fetch_blocking", _boom)
    result, why = asyncio.run(
        fetch_tls("https://target.example/", _gate("target.example"))
    )
    assert result is None
    assert "handshake with target.example:443 did not complete" in why
    assert "connection refused" in why       # the cause survives, not just the fact


def test_an_in_scope_host_is_probed_with_its_own_host_port_and_timeout(monkeypatch):
    seen = {}

    def _record(host, port, timeout):
        seen.update(host=host, port=port, timeout=timeout)
        return ("cert-sentinel", "TLSv1.3")

    monkeypatch.setattr(tls_module, "_fetch_blocking", _record)
    result, why = asyncio.run(
        fetch_tls("https://target.example:8443/deep/path", _gate("target.example"), timeout=3.0)
    )
    assert result == ("cert-sentinel", "TLSv1.3")
    assert why is None, "a successful handshake must not also report a problem"
    assert seen == {"host": "target.example", "port": 8443, "timeout": 3.0}


def test_a_non_https_url_is_skipped_without_needing_authorization(monkeypatch):
    """Ordering check: "nothing to probe" is decided before authorization.

    Nothing has been reached at this point, so there is nothing to authorize --
    the ``_tripwire`` fires if the socket is opened anyway. The reason is a
    backstop: the real caller filters plain HTTP out first and emits a better
    sentence for it, so this branch is unreachable from the scanner.
    """
    monkeypatch.setattr(tls_module, "_fetch_blocking", _tripwire)
    result, why = asyncio.run(fetch_tls("http://target.example/", _gate()))
    assert result is None
    assert "not an https URL" in why
