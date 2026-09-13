from scanner.core.finding import Severity
from scanner.core.rule_id import is_valid
from scanner.scanners.dast.fingerprint import check_fingerprint


def _ids(findings):
    return {f.rule_id for f in findings}


def test_no_leaky_headers_means_no_findings():
    assert check_fingerprint("https://example.com/", {"Server": "cloudflare"}) == []


def test_server_header_with_a_version_is_flagged():
    findings = check_fingerprint("https://example.com/", {"Server": "Apache/2.4.29 (Ubuntu)"})
    assert _ids(findings) == {"dast.fingerprint.server-version"}
    f = findings[0]
    assert is_valid(f.rule_id)
    assert f.scanner == "dast"
    assert f.severity is Severity.LOW
    assert "Apache/2.4.29" in f.evidence
    assert f.fix is None


def test_x_powered_by_is_flagged():
    findings = check_fingerprint("https://example.com/", {"X-Powered-By": "PHP/7.2.1"})
    assert "dast.fingerprint.x-powered-by" in _ids(findings)


def test_aspnet_version_header_is_flagged():
    findings = check_fingerprint("https://example.com/", {"X-AspNet-Version": "4.0.30319"})
    assert "dast.fingerprint.aspnet-version" in _ids(findings)


def test_header_lookup_is_case_insensitive():
    findings = check_fingerprint("https://example.com/", {"server": "nginx/1.18.0"})
    assert "dast.fingerprint.server-version" in _ids(findings)
