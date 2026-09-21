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


# ── the value of SameSite, which nothing read (D77) ──────────────────────────
#
# Secure and HttpOnly have no values, so presence is the whole of them. SameSite
# has three, one of which switches the protection off, and grading all three the
# same way graded the weakest one as compliance.


def _perfect(samesite: str | None = "Strict", *, secure: bool = True) -> str:
    """A cookie with nothing else wrong with it, so one attribute is under test.

    Built rather than written out per case because the point of most of these is a
    single difference from a cookie that is otherwise clean: if any other flag were
    missing too, the assertion would pass on a finding it did not mean.
    """
    parts = ["sid=abc", "HttpOnly"]
    if secure:
        parts.insert(1, "Secure")
    if samesite is not None:
        parts.append(samesite)
    return "; ".join(parts)


def test_the_explicit_opt_out_is_reported_and_used_not_to_be():
    """``SameSite=None`` permits cross-site sending. It is therefore at least as
    exposed as an absent attribute on every client, and more exposed on the ones
    that default an absent attribute to Lax -- and it was the one spelling of this
    cookie that produced no finding at all. Measured before the fix: a clean bill."""
    findings = check_cookies("https://example.com/", [_perfect("SameSite=None")])

    assert _ids(findings) == {"dast.cookies.samesite-none"}
    # Same exposure as the absent case, so the same severity. Asserted against the
    # other rule rather than against a literal, so changing one moves both or fails.
    absent = check_cookies("https://example.com/", [_perfect(None)])
    assert findings[0].severity is absent[0].severity is Severity.LOW
    # A header is whatever the server wrote. Both halves are case-insensitive here
    # for the same reason `test_flag_parsing_is_case_insensitive` covers the flags.
    for spelling in ("SameSite=none", "samesite=NONE", "SAMESITE=None"):
        assert _ids(check_cookies("https://example.com/", [_perfect(spelling)])) == {
            "dast.cookies.samesite-none"
        }, spelling


def test_opting_out_and_omitting_are_different_findings_never_both():
    """The operator's next edit differs -- add the attribute, or change its value --
    so the two states have their own rule IDs, and no cookie is in both."""
    opted_out = _ids(check_cookies("https://example.com/", [_perfect("SameSite=None")]))
    omitted = _ids(check_cookies("https://example.com/", [_perfect(None)]))

    assert opted_out == {"dast.cookies.samesite-none"}
    assert omitted == {"dast.cookies.missing-samesite"}
    assert not opted_out & omitted


def test_a_protective_value_is_clean_in_either_spelling_and_either_case():
    """The guard on the new branches. A check that reports the opt-out is no use if
    it also reports the two values that are the remediation for it."""
    for value in ("SameSite=Strict", "SameSite=Lax", "samesite=LAX", "SameSite=lax"):
        assert check_cookies("https://example.com/", [_perfect(value)]) == [], value


def test_none_without_secure_says_the_cookie_is_discarded_at_all():
    """Browsers require Secure alongside ``SameSite=None`` and drop the cookie
    without it, so the operator has neither the cross-site cookie they asked for nor
    the protection they gave up for it. On plain HTTP nothing else says so:
    ``missing-secure`` is deliberately HTTPS-only, so this cookie scored clean."""
    findings = check_cookies("http://example.com/", [_perfect("SameSite=None", secure=False)])

    assert _ids(findings) == {"dast.cookies.samesite-none"}
    assert "discard" in findings[0].evidence
    assert "Secure" in findings[0].evidence
    # And the clause is not boilerplate: a cookie that does pair them must not
    # carry a sentence saying browsers throw it away.
    paired = check_cookies("https://example.com/", [_perfect("SameSite=None")])
    assert "discard" not in paired[0].evidence


def test_an_unrecognized_value_is_reported_and_quoted_back():
    """A typo'd value is not a stricter one: the client falls back to its default as
    though the attribute were absent, while the response header reads as though a
    protection had been set. Quoting the value is the whole use of the finding --
    "SameSite is wrong" does not tell anyone which character to change."""
    findings = check_cookies("https://example.com/", [_perfect("SameSite=Strcit")])

    assert _ids(findings) == {"dast.cookies.samesite-unrecognized"}
    assert "Strcit" in findings[0].evidence
    assert "Lax" in findings[0].remediation and "Strict" in findings[0].remediation


def test_a_bare_samesite_with_no_value_is_unrecognized_not_present():
    """``Set-Cookie: sid=abc; SameSite`` is the likeliest way to write this wrong,
    because the other two attributes it sits beside are valueless and it looks like
    them. A presence check called it compliant twice over."""
    findings = check_cookies("https://example.com/", [_perfect("SameSite")])

    assert _ids(findings) == {"dast.cookies.samesite-unrecognized"}
    assert "no value" in findings[0].evidence


def test_a_repeated_attribute_is_graded_on_the_value_a_client_would_use():
    """RFC 6265 has the last occurrence win, so a header that appends
    ``SameSite=None`` after ``SameSite=Lax`` is a cookie with no protection and must
    read as one. The reverse is genuinely clean and must not be reported."""
    last_wins = check_cookies(
        "https://example.com/", ["sid=abc; Secure; HttpOnly; SameSite=Lax; SameSite=None"]
    )
    assert _ids(last_wins) == {"dast.cookies.samesite-none"}

    reversed_ = check_cookies(
        "https://example.com/", ["sid=abc; Secure; HttpOnly; SameSite=None; SameSite=Lax"]
    )
    assert reversed_ == []


def test_a_hostile_samesite_value_cannot_inflate_a_finding():
    """The value is the target's text quoted into our prose, which is the exposure
    D44 measured for the cookie *name*.

    The ``evidence`` cap alone keeps the field short, so length is not what this
    test is for. It is for what the cap cuts to get there: the value sits early in
    the sentence and the reason an unrecognized value matters sits after it, so a
    4000-character value bounded only at the field produces a finding that quotes
    the whole hostile string and then stops. Bounding the fragment keeps both.
    """
    findings = check_cookies(
        "https://example.com/", [_perfect("SameSite=" + "z" * 4000)]
    )

    assert len(findings) == 1
    f = findings[0]
    assert len(f.title) <= TITLE_MAX_LEN
    assert len(f.remediation) <= REMEDIATION_MAX_LEN
    assert len(f.evidence) <= EVIDENCE_MAX_LEN
    assert len(build_prompt(f)) < 2000
    # Short is not enough: the sentence has to survive and still say what was found,
    # or the finding is a hostile string with a truncation marker on the end.
    assert "unrecognized SameSite value" in f.title
    assert "No browser recognizes it" in f.evidence, "the value ate the explanation"
    assert not f.evidence.endswith("... (truncated)")


def test_the_value_never_becomes_the_location():
    """Contract §8 keys dedup on location, and location.param is the cookie. Putting
    the offending value there would split one cookie's findings across two keys and
    point the report at something that is not a cookie name."""
    for raw in (_perfect("SameSite=None"), _perfect("SameSite=Strcit"), _perfect("SameSite")):
        for f in check_cookies("https://example.com/", [raw]):
            assert f.location.param == "sid", raw


def test_the_new_rules_are_shaped_like_the_ones_they_sit_beside():
    """A new rule ID is not a new kind of finding. Asserted for the same fields the
    original three are, because a report groups, dedups and renders on them."""
    raws = [_perfect("SameSite=None"), _perfect("SameSite=Strcit"), _perfect("SameSite")]
    findings = [f for raw in raws for f in check_cookies("https://example.com/", [raw])]

    assert len(findings) == 3
    for f in findings:
        assert is_valid(f.rule_id), f.rule_id
        assert f.rule_id.startswith("dast.cookies.")
        assert f.scanner == "dast"
        assert f.location.kind is LocationKind.URL
        assert f.fix is None
        assert f.severity is Severity.LOW
        assert "sid" in f.title and "sid" in f.remediation
