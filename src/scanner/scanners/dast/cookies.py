"""Passive cookie-flag analysis (``dast.cookies.*``).

Given the raw ``Set-Cookie`` header values from one response, flag cookies that
omit the protective attributes: ``Secure`` (keeps the cookie off plaintext HTTP),
``HttpOnly`` (hides it from JavaScript, blunting XSS theft), and ``SameSite``
(reduces cross-site request forgery exposure). One finding per (cookie, issue),
with the cookie name in the finding's location so a report points precisely.

Two of those three are attributes, and a presence check is the whole of them.
``SameSite`` is not: it carries a value, and one of its values is the explicit
opt-out from the protection it exists to provide. Grading it on presence alone
graded it backwards — ``SameSite=None`` passed clean while omitting the attribute
was reported, and omitting it is what modern browsers default to ``Lax`` (D77).
"""

from __future__ import annotations

from scanner.core.finding import FRAGMENT_MAX_LEN, Confidence, Finding, Severity, bounded
from scanner.core.location import Location

_OWASP_COOKIES = "https://owasp.org/www-community/controls/SecureCookieAttribute"

#: The ``SameSite`` values that restrict cross-site sending. ``None`` is a fourth
#: recognized value and is deliberately absent: it is the setting that turns the
#: restriction off, so grouping it with these two is the defect D77 fixed.
_SAMESITE_PROTECTIVE = frozenset({"strict", "lax"})


def _parse_cookie(raw: str) -> tuple[str, dict[str, str]]:
    """Return the cookie name and its attributes, lowercased name to raw value.

    A mapping rather than a set of names, because one of these attributes is graded
    on what it says and not on whether it is there. The previous docstring stated
    the assumption this function was built on — "the value itself is not needed for
    a presence check" — and that holds for ``Secure`` and ``HttpOnly``, which have
    no values, and fails for ``SameSite``, which has three (D77).

    An attribute sent with no ``=`` maps to ``""``. A repeated attribute keeps the
    last value, which is what RFC 6265 says a client does. Membership tests read the
    same on a dict as on a set, so the two checks that only ask whether an attribute
    is present are unchanged by this.
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return "", {}
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
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
        # The target chose this name. Bound it once, here, where it enters our
        # prose: every use below — title, remediation, evidence and
        # location.param — is downstream of this line, and location cannot be
        # bounded at the field because the fingerprint keys on it (D52).
        name = bounded(name, FRAGMENT_MAX_LEN)

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

        findings += _check_samesite(url, name, attrs)

    return findings


def _check_samesite(url: str, name: str, attrs: dict[str, str]) -> list[Finding]:
    """Grade the ``SameSite`` attribute on its value, in three exclusive branches.

    Absent, opted out, and misspelled are three different states of one attribute
    and the operator's next edit differs for each, so each gets its own rule ID and
    no cookie produces two of them.

    **Absent** is the original check and is unchanged. It stays a finding even though
    Chromium-family browsers default an absent ``SameSite`` to ``Lax``, because that
    default is the browser's and not the site's: an older client, or one that changes
    its mind, sends the cookie cross-site and the response header never said not to.

    **``None``** is the state this function exists for. It is the value that permits
    cross-site sending, so it is at least as exposed as an absent attribute on every
    client and strictly more exposed on the ones that default to ``Lax`` — and it was
    the one spelling of this cookie that produced no finding at all. Reported at the
    same severity as the absent case because it is the same exposure, not a worse one.

    **Anything else**, including a bare ``SameSite`` with no value, is a value no
    client recognizes, so the client falls back to its default exactly as though the
    attribute had not been sent. That is the shape ``Config.load``'s closed-set check
    already guards against in this project's own config file: a header that appears to
    claim a protection and does not carry one is worse than a header that claims
    nothing, because the reader stops looking.
    """
    if "samesite" not in attrs:
        return [_finding(
            url, name, "dast.cookies.missing-samesite",
            f"Cookie '{name}' is missing the SameSite attribute",
            Severity.LOW,
            f"Set-Cookie for '{name}' has no SameSite attribute.",
            f"Set SameSite=Lax or Strict on '{name}' to reduce cross-site "
            "request forgery exposure.",
        )]

    value = attrs["samesite"]
    if value.lower() == "none":
        # A cookie carrying SameSite=None and no Secure is discarded outright by
        # every browser that enforces the pairing, so the operator has neither the
        # cross-site cookie they asked for nor the protection they gave up to get
        # it. Said in the evidence rather than raised in severity: a cookie that
        # never reaches the client is not a larger exposure than one that does, it
        # is a configuration that is not in force, and the sentence is what the
        # reader needs. On HTTPS `missing-secure` above has already said the rest.
        discarded = (
            " It also has no Secure attribute, which browsers require alongside "
            "SameSite=None, so those browsers discard the cookie entirely."
            if "secure" not in attrs else ""
        )
        return [_finding(
            url, name, "dast.cookies.samesite-none",
            f"Cookie '{name}' sets SameSite=None",
            Severity.LOW,
            f"Set-Cookie for '{name}' has SameSite=None, which permits the cookie "
            f"to be sent on cross-site requests.{discarded}",
            f"Set SameSite=Lax or Strict on '{name}' unless it is genuinely needed "
            "on cross-site requests; if it is, keep None and add Secure, which "
            "browsers require with it.",
        )]

    if value.lower() not in _SAMESITE_PROTECTIVE:
        # Quoted rather than described, because naming the typo is the whole use of
        # this finding: "SameSite is wrong" does not say which character to change.
        #
        # Which means the target's own text is in our prose, and bounding it at the
        # fragment rather than leaving it to the ``evidence`` cap is the difference
        # D44 turns on. The cap would keep the field short either way; it would keep
        # it short by cutting the sentence off after the value, and the part it cut
        # is the part that says why an unrecognized value matters.
        shown = bounded(value, FRAGMENT_MAX_LEN)
        said = f"SameSite={shown}" if shown else "a SameSite attribute with no value"
        return [_finding(
            url, name, "dast.cookies.samesite-unrecognized",
            f"Cookie '{name}' has an unrecognized SameSite value",
            Severity.LOW,
            f"Set-Cookie for '{name}' has {said}. No browser recognizes it, so each "
            f"one falls back to its own default as if the attribute were absent.",
            f"Set SameSite to Lax, Strict or None on '{name}'; Lax or Strict is what "
            "reduces cross-site request forgery exposure.",
        )]

    return []
