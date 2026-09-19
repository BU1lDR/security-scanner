import json

import pytest

from scanner.core.context import ScanError
from scanner.core.engine import ScanReport
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.fix import Fix, FixKind
from scanner.core.location import Location
from scanner.core.reporting import render


def _f(rule_id="dast.tls.expired-cert", severity=Severity.HIGH,
       confidence=Confidence.FIRM, scanner="dast", title="Bad thing",
       location=None, fix=None, references=None):
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        location=location or Location.for_url("https://example.com/", method="GET"),
        evidence="evidence-text",
        remediation="do the thing",
        scanner=scanner,
        references=references or ["CWE-295"],
        fix=fix,
    )


# --- dispatch ---

def test_unknown_format_raises():
    with pytest.raises(ValueError):
        render(ScanReport(findings=[], errors=[]), fmt="pdf")


# --- terminal ---

def test_terminal_lists_finding_and_groups_by_family():
    report = ScanReport(
        findings=[
            _f(rule_id="dast.tls.expired-cert", severity=Severity.HIGH),
            _f(rule_id="sca.vuln.osv", severity=Severity.CRITICAL, scanner="sca",
               location=Location.for_dependency("PyPI", "requests", "2.0.0")),
        ],
        errors=[],
    )
    out = render(report, fmt="terminal")
    assert "dast.tls.expired-cert" in out
    assert "Bad thing" in out
    assert "HIGH" in out
    # family grouping headers (case-insensitive check on the family token)
    assert "dast" in out.lower()
    assert "sca" in out.lower()


def test_terminal_reports_no_findings_cleanly():
    out = render(ScanReport(findings=[], errors=[]), fmt="terminal")
    assert "No findings" in out


def test_terminal_includes_scan_errors():
    report = ScanReport(
        findings=[],
        errors=[ScanError(scanner="dast", check="tls", message="handshake boom")],
    )
    out = render(report, fmt="terminal")
    assert "handshake boom" in out


# --- json ---

def test_json_is_parseable_and_carries_finding_fields():
    fix = Fix(kind=FixKind.DEPENDENCY_BUMP, description="bump", apply_safe=True,
              details={"to": "2.1.0"})
    report = ScanReport(
        findings=[_f(scanner="sca", rule_id="sca.vuln.osv",
                     location=Location.for_dependency("PyPI", "requests", "2.0.0"),
                     fix=fix)],
        errors=[ScanError(scanner="sca", check="osv", message="rate limited")],
    )
    doc = json.loads(render(report, fmt="json"))
    assert len(doc["findings"]) == 1
    finding = doc["findings"][0]
    assert finding["rule_id"] == "sca.vuln.osv"
    assert finding["severity"] == "HIGH"
    assert finding["family"] == "sca"
    assert finding["fingerprint"]  # non-empty
    assert finding["fix"]["kind"] == "dependency_bump"
    assert finding["location"]["package"] == "requests"
    assert doc["errors"][0]["message"] == "rate limited"
    assert doc["summary"]["high"] == 1


def test_json_omits_null_location_fields():
    doc = json.loads(render(ScanReport(findings=[_f()], errors=[]), fmt="json"))
    loc = doc["findings"][0]["location"]
    assert loc["kind"] == "url"
    assert "package" not in loc  # URL finding has no dependency fields


# --- html ---

def test_html_is_a_document_and_escapes_content():
    report = ScanReport(findings=[_f(title="<script>alert(1)</script>")], errors=[])
    out = render(report, fmt="html")
    assert "<html" in out.lower()
    assert "<script>alert(1)</script>" not in out  # must be escaped
    assert "&lt;script&gt;" in out


# ── every format discloses that attack traffic was sent ──────────────────────
#
# All three, because the format is the reader's choice and the disclosure is not.
# A JSON consumer wiring this into a pipeline and a person reading the terminal
# output have the same need to know what the scan did to the target. See D49.

class _Target:
    url = "https://example.com/"


def _active_report():
    return ScanReport(
        findings=[],
        scanners_run=["dast", "dast-active"],
        active_scanners_run=["dast-active"],
    )


def _passive_report():
    return ScanReport(findings=[], scanners_run=["dast"])


def test_terminal_says_active_checks_ran():
    out = render(_active_report(), "terminal", target=_Target())
    assert "Ran: dast, dast-active" in out
    assert "ACTIVE CHECKS RAN" in out
    assert "attack-shaped requests" in out


def test_terminal_discloses_it_near_the_top_not_buried():
    """Position is the feature.

    A disclosure under the findings is one a reader scrolls past on a long report.
    This asserts it lands above the findings, so it is seen without being sought.
    """
    report = ScanReport(
        findings=[_f()],
        scanners_run=["dast", "dast-active"],
        active_scanners_run=["dast-active"],
    )
    out = render(report, "terminal", target=_Target())
    assert out.index("ACTIVE CHECKS RAN") < out.index("dast.tls.expired-cert")


def test_terminal_says_nothing_of_the_sort_for_a_passive_scan():
    out = render(_passive_report(), "terminal", target=_Target())
    assert "Ran: dast" in out
    assert "ACTIVE" not in out


def test_json_carries_the_scan_record():
    doc = json.loads(render(_active_report(), "json", target=_Target()))
    assert doc["scan"] == {
        "scanners_run": ["dast", "dast-active"],
        "active_scanners_run": ["dast-active"],
        "sent_active_traffic": True,
    }


def test_json_scan_record_is_false_for_a_passive_scan():
    doc = json.loads(render(_passive_report(), "json", target=_Target()))
    assert doc["scan"]["sent_active_traffic"] is False
    assert doc["scan"]["active_scanners_run"] == []


def test_html_carries_the_disclosure_emphasised():
    out = render(_active_report(), "html", target=_Target())
    assert "ACTIVE CHECKS RAN" in out
    assert "<strong>ACTIVE CHECKS RAN" in out, "should not be a quiet aside"


def test_html_escapes_the_scanner_names():
    """Scanner names reach the page, so they are escaped like everything else."""
    report = ScanReport(
        findings=[],
        scanners_run=["<script>alert(1)</script>"],
        active_scanners_run=["<script>alert(1)</script>"],
    )
    out = render(report, "html", target=_Target())
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


@pytest.mark.parametrize("fmt", ["terminal", "html"])
def test_an_unrecorded_scan_claims_nothing_either_way(fmt):
    """A hand-built report must not read as a passive scan.

    Absent evidence is not evidence of absence, and this field is the one place in
    the report where inventing a reassuring default would be actively harmful.
    """
    out = render(ScanReport(findings=[]), fmt, target=_Target())
    assert "ACTIVE" not in out
    assert "Ran:" not in out


def test_json_omits_the_scan_block_when_nothing_was_recorded():
    """Not `"sent_active_traffic": false`, which would be a claim.

    A pipeline gating on this key should get a missing key it has to handle rather
    than a reassuring default it will not question. This is the JSON equivalent of
    the two tests above printing nothing.
    """
    doc = json.loads(render(ScanReport(findings=[]), "json", target=_Target()))
    assert "scan" not in doc
