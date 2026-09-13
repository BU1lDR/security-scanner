from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanner.core.finding import Severity
from scanner.core.location import LocationKind
from scanner.core.rule_id import is_valid
from scanner.scanners.dast.tls import analyze_tls

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
