from scanner.ai.advisor import build_prompt
from scanner.core.finding import (
    EVIDENCE_MAX_LEN,
    FRAGMENT_MAX_LEN,
    REMEDIATION_MAX_LEN,
    TITLE_MAX_LEN,
    Severity,
)
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


def test_a_hostile_cookie_name_cannot_inflate_a_finding():
    """The name comes from the target. D44 measured what that cost: a 4000-char
    cookie name produced a 4036-char title, a 4071-char remediation and a
    12,900-char AI prompt, because only ``evidence`` was bounded. The bound is now
    on the name itself, at the interpolation, so every field is short."""
    findings = check_cookies("https://example.com/", ["a" * 4000 + "=v"])

    assert len(findings) == 3
    for f in findings:
        assert len(f.title) <= TITLE_MAX_LEN
        assert len(f.remediation) <= REMEDIATION_MAX_LEN
        assert len(f.evidence) <= EVIDENCE_MAX_LEN
        assert len(f.location.param) <= FRAGMENT_MAX_LEN, "location is unbounded"
        assert len(build_prompt(f)) < 2000
        # Short is necessary but not sufficient: a title truncated at the field cap
        # is also short, and says nothing. The bound has to leave the sentence
        # intact, so assert the finding still states what it is.
        assert "is missing the" in f.title, "the hostile name ate the title"
        assert not f.title.endswith("... (truncated)")


def test_an_ordinary_cookie_name_is_still_quoted_in_full():
    """The bound must not cost a real report anything: names are tens of
    characters, so the only finding that changes is the hostile one."""
    findings = check_cookies("https://example.com/", ["session_id_for_the_app=abc"])
    for f in findings:
        assert "session_id_for_the_app" in f.title
        assert f.location.param == "session_id_for_the_app"
