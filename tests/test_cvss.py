import pytest

from scanner.core.finding import Severity
from scanner.scanners.sca.cvss import base_score, score_to_severity


@pytest.mark.parametrize(
    "vector,expected",
    [
        # Canonical CVSS 3.1 worked examples (spec values).
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_matches_spec(vector, expected):
    assert base_score(vector) == expected


def test_base_score_handles_scope_changed():
    # Scope change multiplies the combined score by 1.08.
    score = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score == 10.0


def test_base_score_returns_none_for_unsupported_vector():
    assert base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None  # CVSS v2
    assert base_score("garbage") is None
    assert base_score("") is None


@pytest.mark.parametrize(
    "score,severity",
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_score_to_severity_buckets(score, severity):
    assert score_to_severity(score) is severity
