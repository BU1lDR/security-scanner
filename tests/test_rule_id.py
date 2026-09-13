import pytest

from scanner.core.rule_id import family, is_valid, validate


@pytest.mark.parametrize(
    "rid",
    [
        "sca.vuln.osv",
        "dast.headers.missing-hsts",
        "dast.active.xss-reflected",
        "dast.active.open-redirect",
        "sast.secret.aws-access-key",
        "sast.sink.python-eval",
        "dast.headers.csp.missing",  # four segments is allowed (at least three)
    ],
)
def test_valid_rule_ids_pass(rid):
    assert is_valid(rid)
    validate(rid)  # does not raise


@pytest.mark.parametrize(
    "rid",
    [
        "DAST.headers.missing-hsts",  # uppercase family
        "dast.Headers.missing-hsts",  # uppercase category segment
        "dast.headers.Missing-hsts",  # uppercase name segment
        "sca.vuln.OSV",  # uppercase within a name segment
        "web.xss.reflected",  # unknown family
        "dast.headers",  # too few segments
        "dast",  # too few segments
        "dast.headers.",  # trailing dot / empty segment
        "dast..missing",  # empty middle segment
        "dast.headers.missing hsts",  # space
        "dast.headers.-hsts",  # leading hyphen in segment
        "",  # empty
    ],
)
def test_invalid_rule_ids_are_rejected(rid):
    assert not is_valid(rid)
    with pytest.raises(ValueError):
        validate(rid)


def test_family_returns_the_first_segment():
    assert family("dast.active.xss-reflected") == "dast"
    assert family("sca.vuln.osv") == "sca"
    assert family("sast.secret.aws-access-key") == "sast"


def test_family_of_invalid_id_raises():
    with pytest.raises(ValueError):
        family("web.nope.nope")
