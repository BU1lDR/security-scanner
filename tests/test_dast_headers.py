from scanner.core.finding import Confidence, Severity
from scanner.core.location import LocationKind
from scanner.core.rule_id import is_valid
from scanner.scanners.dast.headers import check_security_headers

_GOOD = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def _ids(findings):
    return {f.rule_id for f in findings}


def test_fully_hardened_https_response_has_no_header_findings():
    assert check_security_headers("https://example.com/", _GOOD) == []


def test_bare_https_response_flags_the_standard_missing_headers():
    findings = check_security_headers("https://example.com/", {})
    assert _ids(findings) == {
        "dast.headers.missing-hsts",
        "dast.headers.missing-csp",
        "dast.headers.missing-x-content-type-options",
        "dast.headers.missing-x-frame-options",
        "dast.headers.missing-referrer-policy",
    }
    for f in findings:
        assert is_valid(f.rule_id)
        assert f.scanner == "dast"
        assert f.location.kind is LocationKind.URL
        assert f.location.url == "https://example.com/"
        assert f.confidence is Confidence.FIRM
        assert f.fix is None  # a live app has no file to patch (contract §7)


def test_hsts_is_only_expected_on_https():
    findings = check_security_headers("http://example.com/", {})
    assert "dast.headers.missing-hsts" not in _ids(findings)
    # the transport-independent headers are still flagged
    assert "dast.headers.missing-csp" in _ids(findings)


def test_header_lookup_is_case_insensitive():
    lower = {k.lower(): v for k, v in _GOOD.items()}
    assert check_security_headers("https://example.com/", lower) == []


def test_csp_frame_ancestors_satisfies_clickjacking_protection():
    headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
    findings = check_security_headers("https://example.com/", headers)
    # X-Frame-Options absent, but CSP frame-ancestors covers clickjacking.
    assert "dast.headers.missing-x-frame-options" not in _ids(findings)


def test_missing_hsts_is_medium_and_x_content_type_is_low():
    findings = {f.rule_id: f for f in check_security_headers("https://example.com/", {})}
    assert findings["dast.headers.missing-hsts"].severity is Severity.MEDIUM
    assert findings["dast.headers.missing-x-content-type-options"].severity is Severity.LOW
