from scanner.core.finding import Severity
from scanner.core.location import LocationKind
from scanner.core.rule_id import is_valid
from scanner.scanners.dast.cookies import check_cookies


def _ids(findings):
    return {f.rule_id for f in findings}


def test_fully_flagged_cookie_on_https_has_no_findings():
    raw = ["sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict"]
    assert check_cookies("https://example.com/", raw) == []


def test_bare_cookie_on_https_flags_all_three_weaknesses():
    findings = check_cookies("https://example.com/", ["sid=abc; Path=/"])
    assert _ids(findings) == {
        "dast.cookies.missing-secure",
        "dast.cookies.missing-httponly",
        "dast.cookies.missing-samesite",
    }
    for f in findings:
        assert is_valid(f.rule_id)
        assert f.scanner == "dast"
        assert f.location.kind is LocationKind.URL
        assert f.location.param == "sid"   # the finding points at the cookie
        assert f.fix is None


def test_secure_flag_is_only_expected_on_https():
    findings = check_cookies("http://example.com/", ["sid=abc"])
    assert "dast.cookies.missing-secure" not in _ids(findings)
    assert "dast.cookies.missing-httponly" in _ids(findings)


def test_flag_parsing_is_case_insensitive():
    raw = ["sid=abc; secure; httponly; samesite=lax"]
    assert check_cookies("https://example.com/", raw) == []


def test_each_cookie_is_reported_independently():
    raw = [
        "a=1; Secure; HttpOnly; SameSite=Lax",   # clean
        "b=2; Path=/",                            # weak
    ]
    findings = check_cookies("https://example.com/", raw)
    params = {f.location.param for f in findings}
    assert params == {"b"}


def test_missing_secure_is_medium():
    findings = {f.rule_id: f for f in check_cookies("https://example.com/", ["sid=abc"])}
    assert findings["dast.cookies.missing-secure"].severity is Severity.MEDIUM
