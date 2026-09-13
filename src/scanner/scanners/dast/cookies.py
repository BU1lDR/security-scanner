"""Passive cookie-flag analysis (``dast.cookies.*``).

Given the raw ``Set-Cookie`` header values from one response, flag cookies that
omit the protective attributes: ``Secure`` (keeps the cookie off plaintext HTTP),
``HttpOnly`` (hides it from JavaScript, blunting XSS theft), and ``SameSite``
(reduces cross-site request forgery exposure). One finding per (cookie, issue),
with the cookie name in the finding's location so a report points precisely.
"""

from __future__ import annotations

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location

_OWASP_COOKIES = "https://owasp.org/www-community/controls/SecureCookieAttribute"


def _parse_cookie(raw: str) -> tuple[str, set[str]]:
    """Return the cookie name and the lowercased set of attribute names present.

    A ``SameSite=Lax`` attribute contributes ``"samesite"`` to the set; the value
    itself is not needed for a presence check.
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return "", set()
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
    return name, attrs


def _finding(url: str, name: str, rule_id: str, title: str, severity: Severity,
             evidence: str, remediation: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        location=Location.for_url(url, method="GET", param=name),
        evidence=evidence,
        remediation=remediation,
        scanner="dast",
        references=[_OWASP_COOKIES, "CWE-614"],
        fix=None,
    )


def check_cookies(url: str, set_cookie_values: list[str]) -> list[Finding]:
    is_https = url.lower().startswith("https://")
    findings: list[Finding] = []

    for raw in set_cookie_values:
        name, attrs = _parse_cookie(raw)
        if not name:
            continue

        if is_https and "secure" not in attrs:
            findings.append(_finding(
                url, name, "dast.cookies.missing-secure",
                f"Cookie '{name}' is missing the Secure flag",
                Severity.MEDIUM,
                f"Set-Cookie for '{name}' has no Secure attribute on an HTTPS site.",
                f"Add the Secure attribute to '{name}' so it is never sent over "
                "plaintext HTTP.",
            ))

        if "httponly" not in attrs:
            findings.append(_finding(
                url, name, "dast.cookies.missing-httponly",
                f"Cookie '{name}' is missing the HttpOnly flag",
                Severity.LOW,
                f"Set-Cookie for '{name}' has no HttpOnly attribute.",
                f"Add the HttpOnly attribute to '{name}' so client-side scripts "
                "cannot read it (limits XSS cookie theft).",
            ))

        if "samesite" not in attrs:
            findings.append(_finding(
                url, name, "dast.cookies.missing-samesite",
                f"Cookie '{name}' is missing the SameSite attribute",
                Severity.LOW,
                f"Set-Cookie for '{name}' has no SameSite attribute.",
                f"Set SameSite=Lax or Strict on '{name}' to reduce cross-site "
                "request forgery exposure.",
            ))

    return findings
