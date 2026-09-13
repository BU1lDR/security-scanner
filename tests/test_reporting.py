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
