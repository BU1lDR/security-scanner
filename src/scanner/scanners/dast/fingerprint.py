"""Passive technology/version disclosure (``dast.fingerprint.*``).

Response headers often name the server software and its exact version, which
hands an attacker a shortlist of version-specific exploits to try. We flag the
common offenders. These are low-severity information leaks, not vulnerabilities
in themselves; confidence is FIRM because the header is directly observed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location

_VERSION = re.compile(r"\d")  # a version number leaks only if it contains a digit
_REF = ["https://owasp.org/www-project-web-security-testing-guide/", "CWE-200"]


def _finding(url: str, rule_id: str, title: str, evidence: str, remediation: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.LOW,
        confidence=Confidence.FIRM,
        location=Location.for_url(url, method="GET"),
        evidence=evidence[:300],
        remediation=remediation,
        scanner="dast",
        references=list(_REF),
        fix=None,
    )


def check_fingerprint(url: str, headers: Mapping[str, str]) -> list[Finding]:
    present = {k.lower(): (v or "") for k, v in headers.items()}
    findings: list[Finding] = []

    server = present.get("server", "")
    if server and _VERSION.search(server):
        findings.append(_finding(
            url, "dast.fingerprint.server-version",
            "Server header discloses software version",
            f"Server: {server}",
            "Configure the server to omit or genericize the Server header so it "
            "does not advertise an exact, exploit-searchable version.",
        ))

    powered = present.get("x-powered-by", "")
    if powered:
        findings.append(_finding(
            url, "dast.fingerprint.x-powered-by",
            "X-Powered-By header discloses backend technology",
            f"X-Powered-By: {powered}",
            "Remove the X-Powered-By header; it reveals the backend stack with no "
            "benefit to clients.",
        ))

    aspnet = present.get("x-aspnet-version") or present.get("x-aspnetmvc-version")
    if aspnet:
        findings.append(_finding(
            url, "dast.fingerprint.aspnet-version",
            "ASP.NET version header disclosed",
            f"ASP.NET version: {aspnet}",
            "Disable the X-AspNet-Version / X-AspNetMvc-Version headers (e.g. via "
            "<httpRuntime enableVersionHeader=\"false\"/>).",
        ))

    return findings
