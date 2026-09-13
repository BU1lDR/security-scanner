"""Exposed-file reconnaissance (``dast.exposed.*``).

This lives in the *passive* tier but is honestly more than pure observation: it
sends a few GETs the crawl didn't. It stays in-bounds by strict rules (contract
§12): same-origin only, GET-only, a small curated path list, non-destructive, and
soft-404 calibrated so a site that answers "200 OK" for everything doesn't turn
into a wall of false positives.

Calibration: we first fetch an unlikely path and remember what "not here" looks
like. A probe is only reported when it returns 200 *and* its body matches a
content signature specific to that file (env-var lines, git config markers, …) —
a friendly 404 page won't match those signatures, which is what keeps precision
high. Evidence names the file only; secret *values* are never echoed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location

# An unlikely path used to learn the site's "not found" response.
_CALIBRATION_PATH = "secscan-calibration-404-do-not-exist-9f3a"

_ENV_LINE = re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*=")
_GIT_HEAD = re.compile(r"^(ref:\s+\S+|[0-9a-f]{40})", re.IGNORECASE)


def _looks_like_env(body: str) -> bool:
    return _ENV_LINE.search(body) is not None


def _looks_like_git_config(body: str) -> bool:
    return "[core]" in body


def _looks_like_git_head(body: str) -> bool:
    return _GIT_HEAD.match(body.strip()) is not None


@dataclass(frozen=True)
class _Probe:
    path: str
    rule_id: str
    title: str
    severity: Severity
    signature: Callable[[str], bool]
    remediation: str


_PROBES: tuple[_Probe, ...] = (
    _Probe(
        ".env", "dast.exposed.env-file",
        "Environment file (.env) is publicly readable",
        Severity.HIGH, _looks_like_env,
        "Remove .env from the web root and block dotfiles at the server; rotate "
        "any credentials it contained.",
    ),
    _Probe(
        ".git/config", "dast.exposed.git-dir",
        "Git repository (.git/) is publicly readable",
        Severity.HIGH, _looks_like_git_config,
        "Deny access to the .git directory; source and history disclosure lets "
        "an attacker reconstruct the codebase.",
    ),
    _Probe(
        ".git/HEAD", "dast.exposed.git-dir",
        "Git repository (.git/) is publicly readable",
        Severity.HIGH, _looks_like_git_head,
        "Deny access to the .git directory; source and history disclosure lets "
        "an attacker reconstruct the codebase.",
    ),
)

_REF = ["https://owasp.org/www-project-web-security-testing-guide/", "CWE-538"]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


async def _get(http, url: str):
    try:
        return await http.get(url)
    except Exception:  # noqa: BLE001 - one probe's failure must not sink the rest
        return None


def _matches_baseline(baseline, signature: Callable[[str], bool]) -> bool:
    """True if the site's 'not found' response itself trips the signature — in
    which case a matching probe tells us nothing and must not be reported."""
    return (
        baseline is not None
        and baseline.status_code == 200
        and signature(baseline.text)
    )


async def probe_exposed_files(url: str, http) -> list[Finding]:
    origin = _origin(url)
    baseline = await _get(http, origin + _CALIBRATION_PATH)

    findings: list[Finding] = []
    seen: set[str] = set()
    for probe in _PROBES:
        target = origin + probe.path
        resp = await _get(http, target)
        if resp is None or resp.status_code != 200:
            continue
        if not probe.signature(resp.text):
            continue
        if _matches_baseline(baseline, probe.signature):
            continue
        # De-duplicate probes that map to the same issue (e.g. two .git files).
        key = f"{probe.rule_id}|{target}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            rule_id=probe.rule_id,
            title=probe.title,
            severity=probe.severity,
            confidence=Confidence.FIRM,
            location=Location.for_url(target, method="GET"),
            evidence=f"GET {target} returned 200 with {probe.path}-shaped content.",
            remediation=probe.remediation,
            scanner="dast",
            references=list(_REF),
            fix=None,
        ))
    return findings
