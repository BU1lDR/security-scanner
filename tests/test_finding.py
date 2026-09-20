import pytest

from scanner.core.finding import (
    EVIDENCE_MAX_LEN,
    FRAGMENT_MAX_LEN,
    REMEDIATION_MAX_LEN,
    TITLE_MAX_LEN,
    _TRUNCATION_MARKER,
    Confidence,
    Finding,
    Severity,
    bounded,
)
from scanner.core.fix import Fix, FixKind
from scanner.core.location import Location


def _minimal_finding(**overrides) -> Finding:
    kwargs = dict(
        rule_id="dast.headers.missing-hsts",
        title="Missing HSTS header",
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        location=Location.for_url("https://example.com/", method="GET"),
        evidence="No Strict-Transport-Security header present",
        remediation="Add a Strict-Transport-Security response header.",
        scanner="dast",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def test_severity_orders_from_info_up_to_critical():
    assert (
        Severity.CRITICAL
        > Severity.HIGH
        > Severity.MEDIUM
        > Severity.LOW
        > Severity.INFO
    )


def test_confidence_orders_from_tentative_up_to_confirmed():
    assert Confidence.CONFIRMED > Confidence.FIRM > Confidence.TENTATIVE


def test_finding_stores_its_core_fields():
    f = _minimal_finding()
    assert f.rule_id == "dast.headers.missing-hsts"
    assert f.title == "Missing HSTS header"
    assert f.severity is Severity.MEDIUM
    assert f.confidence is Confidence.FIRM
    assert f.location.url == "https://example.com/"
    assert f.evidence == "No Strict-Transport-Security header present"
    assert f.remediation == "Add a Strict-Transport-Security response header."
    assert f.scanner == "dast"


def test_finding_references_default_to_empty_list():
    assert _minimal_finding().references == []


def test_finding_fix_defaults_to_none():
    assert _minimal_finding().fix is None


def test_finding_accepts_a_structured_fix():
    fix = Fix(kind=FixKind.CONFIG_SNIPPET, description="Add header", apply_safe=True)
    assert _minimal_finding(fix=fix).fix is fix


def test_fingerprint_is_a_sha256_hex_string():
    fp = _minimal_finding().fingerprint
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_same_rule_and_location_produce_the_same_fingerprint():
    assert _minimal_finding().fingerprint == _minimal_finding().fingerprint


def test_different_rule_id_changes_the_fingerprint():
    a = _minimal_finding()
    b = _minimal_finding(rule_id="dast.headers.missing-csp")
    assert a.fingerprint != b.fingerprint


def test_url_query_order_does_not_change_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://example.com/?a=1&b=2"))
    b = _minimal_finding(location=Location.for_url("https://example.com/?b=2&a=1"))
    assert a.fingerprint == b.fingerprint


def test_url_fragment_does_not_change_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://example.com/page"))
    b = _minimal_finding(location=Location.for_url("https://example.com/page#section"))
    assert a.fingerprint == b.fingerprint


def test_different_param_changes_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://example.com/s", param="q"))
    b = _minimal_finding(location=Location.for_url("https://example.com/s", param="id"))
    assert a.fingerprint != b.fingerprint


def test_dependency_fingerprint_keys_on_ecosystem_package_version():
    a = _minimal_finding(
        rule_id="sca.vuln.osv",
        scanner="sca",
        location=Location.for_dependency("PyPI", "requests", version="2.19.0"),
    )
    b = _minimal_finding(
        rule_id="sca.vuln.osv",
        scanner="sca",
        location=Location.for_dependency("PyPI", "requests", version="2.32.0"),
    )
    assert a.fingerprint != b.fingerprint


def test_file_fingerprint_keys_on_path_and_line():
    a = _minimal_finding(
        rule_id="sast.sink.python-eval",
        scanner="sast",
        location=Location.for_file("app.py", line=10),
    )
    b = _minimal_finding(
        rule_id="sast.sink.python-eval",
        scanner="sast",
        location=Location.for_file("app.py", line=20),
    )
    assert a.fingerprint != b.fingerprint


# --- rule_id is validated at construction (contract §5) ---

def test_finding_rejects_an_invalid_rule_id():
    with pytest.raises(ValueError):
        _minimal_finding(rule_id="GARBAGE not a rule id")


# --- fingerprint keys on host, not raw netloc (contract §8: "scheme + host + path") ---

def test_url_host_case_does_not_change_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://Example.com/login", method="GET"))
    b = _minimal_finding(location=Location.for_url("https://example.com/login", method="GET"))
    assert a.fingerprint == b.fingerprint


def test_url_default_port_does_not_change_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://example.com:443/login"))
    b = _minimal_finding(location=Location.for_url("https://example.com/login"))
    assert a.fingerprint == b.fingerprint


def test_url_userinfo_does_not_change_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://user:pw@example.com/login"))
    b = _minimal_finding(location=Location.for_url("https://example.com/login"))
    assert a.fingerprint == b.fingerprint


def test_url_method_changes_the_fingerprint():
    a = _minimal_finding(location=Location.for_url("https://example.com/s", method="GET", param="q"))
    b = _minimal_finding(location=Location.for_url("https://example.com/s", method="POST", param="q"))
    assert a.fingerprint != b.fingerprint


# --- the evidence contract, enforced at the boundary -------------------------

def test_over_long_evidence_is_truncated_and_says_so():
    """The contract on ``Finding.evidence`` said callers must truncate. Eight call
    sites each decided independently and three decided "not at all", so a verbose
    or hostile target could inflate a report without bound. The dataclass now owns
    the invariant, the way ``Fix.__post_init__`` owns ``apply_safe``."""
    f = _minimal_finding(evidence="x" * 5000)

    assert len(f.evidence) == EVIDENCE_MAX_LEN
    assert f.evidence.endswith(_TRUNCATION_MARKER)  # never a silent partial


def test_evidence_at_the_limit_is_left_exactly_alone():
    exact = "y" * EVIDENCE_MAX_LEN
    assert _minimal_finding(evidence=exact).evidence == exact


def test_over_long_evidence_truncates_rather_than_raising():
    """``Fix`` raises on its violated invariant; this one must not.

    ``Fix.apply_safe`` is about the scanner's own code being wrong, so failing
    loudly is right. Evidence length is decided by whatever the *target* returned,
    and a scan must not be killed by a chatty server."""
    _minimal_finding(evidence="z" * 100_000)  # no exception


def test_a_credential_that_slipped_past_a_call_site_is_scrubbed():
    token = "ghp_" + "a" * 36
    f = _minimal_finding(evidence=f"response contained {token} in a header")

    assert token not in f.evidence
    assert "ghp_" in f.evidence          # locator kept, so the finding still reads
    assert "in a header" in f.evidence


def test_evidence_is_scrubbed_before_it_is_truncated():
    """Order is load-bearing, and getting it backwards leaks quietly.

    Truncate first and a token straddling the cut keeps its head in the report as
    plaintext, while the fragment no longer matches any shape — so a later scrub
    can never recover it."""
    token = "ghp_" + "a" * 36
    f = _minimal_finding(evidence="x" * (EVIDENCE_MAX_LEN - 20) + token)

    assert "ghp_" + "a" * 16 not in f.evidence, "a token fragment survived the cut"
    assert token not in f.evidence


def test_already_redacted_evidence_passes_through_unchanged():
    """SAST hands over evidence it already masked. The boundary must not mask the
    mask — evidence would decay a little at every layer it crossed."""
    already = "Hardcoded GitHub token: ghp_" + "*" * 36 + " (value redacted, line 12)"
    assert _minimal_finding(evidence=already).evidence == already


# --- the other three fields a finding carries into a report (D52) ------------

def test_over_long_title_is_capped_and_says_so():
    """D44 measured a 4036-character title from a 4000-character cookie name and
    recorded that the field was untouched. The cap is the backstop half of the
    answer; the fragment bound at the interpolation is the other half."""
    f = _minimal_finding(title="t" * 5000)

    assert len(f.title) == TITLE_MAX_LEN
    assert f.title.endswith(_TRUNCATION_MARKER)


def test_over_long_remediation_is_capped_and_says_so():
    f = _minimal_finding(remediation="r" * 5000)

    assert len(f.remediation) == REMEDIATION_MAX_LEN
    assert f.remediation.endswith(_TRUNCATION_MARKER)


def test_a_credential_in_a_title_or_remediation_is_scrubbed():
    """``title`` and ``remediation`` reach the report and the AI prompt on exactly
    the same terms as ``evidence``, so the scrub cannot stop at one of them."""
    token = "ghp_" + "a" * 36
    f = _minimal_finding(title=f"Token {token} in source", remediation=f"Rotate {token}.")

    assert token not in f.title
    assert token not in f.remediation


def test_a_bounded_fragment_is_short_enough_to_leave_room_for_our_own_prose():
    """The fragment bound exists so a hostile name cannot consume a whole field:
    bounded fragment + the longest sentence any check wraps it in must still fit.

    ``FRAGMENT_MAX_LEN < TITLE_MAX_LEN`` is *not* that property — it permits a
    fragment that fits with nothing left over for the sentence around it. With the
    loose version, any FRAGMENT_MAX_LEN in 158..199 (or any TITLE_MAX_LEN under
    163) left the whole suite green while every hostile-name cookie title became
    padding plus a truncation marker, saying nothing about what was found. The
    wrapper is measured from the longest title any check builds rather than
    hardcoded, so editing that sentence re-checks the bound instead of silently
    eating the slack.
    """
    longest_title = "Cookie '{}' is missing the SameSite attribute"  # dast/cookies.py
    wrapper = len(longest_title.format(""))

    assert len(bounded("x" * 5000, FRAGMENT_MAX_LEN)) == FRAGMENT_MAX_LEN
    assert FRAGMENT_MAX_LEN + wrapper <= TITLE_MAX_LEN
