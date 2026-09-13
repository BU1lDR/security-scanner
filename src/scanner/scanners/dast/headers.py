"""Passive security-header analysis (``dast.headers.*``).

A pure function over one response's headers: it decides which recommended
security headers are absent and turns each absence into a Finding. No network,
no state — the scanner fetches the response and hands us its headers.

We report *missing* headers only (an observed, unambiguous fact). Whether a
missing header is a real risk is contextual, so confidence is FIRM rather than
CONFIRMED. DAST findings never carry a machine fix — a live app has no file to
patch (contract §7).
"""

from __future__ import annotations

from collections.abc import Mapping

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location

_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


def _finding(url: str, rule_id: str, title: str, severity: Severity,
             evidence: str, remediation: str, references: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        location=Location.for_url(url, method="GET"),
        evidence=evidence,
        remediation=remediation,
        scanner="dast",
        references=references,
        fix=None,
    )


def check_security_headers(url: str, headers: Mapping[str, str]) -> list[Finding]:
    """Findings for recommended security headers absent from ``headers``."""
    present = {k.lower(): (v or "") for k, v in headers.items()}
    findings: list[Finding] = []

    if url.lower().startswith("https://") and "strict-transport-security" not in present:
        findings.append(_finding(
            url,
            "dast.headers.missing-hsts",
            "Missing Strict-Transport-Security header",
            Severity.MEDIUM,
            "No Strict-Transport-Security response header was set.",
            "Send 'Strict-Transport-Security: max-age=63072000; includeSubDomains' "
            "so browsers refuse to talk to the site over plain HTTP.",
            [_OWASP_HEADERS, "CWE-319"],
        ))

    if "content-security-policy" not in present:
        findings.append(_finding(
            url,
            "dast.headers.missing-csp",
            "Missing Content-Security-Policy header",
            Severity.MEDIUM,
            "No Content-Security-Policy response header was set.",
            "Define a Content-Security-Policy to constrain which scripts, styles, "
            "and frames the page may load, reducing XSS impact.",
            [_OWASP_HEADERS, "CWE-1021"],
        ))

    if "x-content-type-options" not in present:
        findings.append(_finding(
            url,
            "dast.headers.missing-x-content-type-options",
            "Missing X-Content-Type-Options header",
            Severity.LOW,
            "No 'X-Content-Type-Options: nosniff' response header was set.",
            "Send 'X-Content-Type-Options: nosniff' to stop browsers guessing "
            "(MIME-sniffing) a response's content type.",
            [_OWASP_HEADERS, "CWE-16"],
        ))

    # Clickjacking is covered by EITHER X-Frame-Options or CSP frame-ancestors.
    csp = present.get("content-security-policy", "")
    if "x-frame-options" not in present and "frame-ancestors" not in csp.lower():
        findings.append(_finding(
            url,
            "dast.headers.missing-x-frame-options",
            "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
            Severity.MEDIUM,
            "Neither X-Frame-Options nor a CSP 'frame-ancestors' directive was set.",
            "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive to "
            "prevent the page from being framed by other sites (clickjacking).",
            [_OWASP_HEADERS, "CWE-1021"],
        ))

    if "referrer-policy" not in present:
        findings.append(_finding(
            url,
            "dast.headers.missing-referrer-policy",
            "Missing Referrer-Policy header",
            Severity.LOW,
            "No Referrer-Policy response header was set.",
            "Send a Referrer-Policy (e.g. 'no-referrer' or 'strict-origin-when-"
            "cross-origin') to limit how much URL information leaks to other sites.",
            [_OWASP_HEADERS, "CWE-200"],
        ))

    return findings
