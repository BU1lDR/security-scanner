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
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location
from scanner.scanners.dast.crawler import why_exception

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


@dataclass(frozen=True)
class ExposedProblem:
    """A probe that did not complete, which is not a file that is not there.

    ``kind`` is a stable slug, mirroring ``CrawlProblem``, because these are not the
    same size of thing. ``probe-failed`` is one path this check could not ask about.
    ``calibration-failed`` is worse: the soft-404 baseline never loaded, so the guard
    that stops a site answering 200 for everything from becoming three false
    positives was not in effect for any probe that followed.

    ``detail`` is for a human reading the report and never carries a response body —
    only exception class names and the URL we asked for.
    """

    url: str
    kind: str
    detail: str


@dataclass
class ExposedResult:
    """What the probes found, and what they could not ask.

    The second list is why this is a result object rather than a list of findings.
    This check's entire output is an absence, so "nothing came back" and "nothing is
    there" render identically unless the failures travel alongside the findings.
    """

    findings: list[Finding] = field(default_factory=list)
    problems: list[ExposedProblem] = field(default_factory=list)


async def _get(http, url: str) -> tuple[object | None, str | None]:
    """Fetch one probe as ``(response, None)`` or ``(None, reason)``.

    One probe's failure must not sink the rest — but the bare ``None`` this used to
    return made "we could not ask" indistinguishable from "the file is not there",
    and line for line the caller then treated them the same way. A host that refused
    every connection came back as a clean bill of health for three files nobody had
    looked at (D66).
    """
    try:
        return await http.get(url), None
    except Exception as exc:  # noqa: BLE001 - one probe's failure must not sink the rest
        return None, why_exception(exc)


def _matches_baseline(baseline, signature: Callable[[str], bool]) -> bool:
    """True if the site's 'not found' response itself trips the signature — in
    which case a matching probe tells us nothing and must not be reported."""
    return (
        baseline is not None
        and baseline.status_code == 200
        and signature(baseline.text)
    )


async def probe_exposed_files(url: str, http) -> ExposedResult:
    origin = _origin(url)
    result = ExposedResult()

    calibration_url = origin + _CALIBRATION_PATH
    baseline, why = await _get(http, calibration_url)
    if why is not None:
        # Not one missing data point among four. Without a baseline
        # ``_matches_baseline`` returns False for every probe, so the precision guard
        # is off rather than absent-and-announced — and it fails in the loud
        # direction, which is the one nobody investigates for being too quiet.
        result.problems.append(ExposedProblem(
            calibration_url, "calibration-failed",
            f"the soft-404 baseline could not be fetched, so any hit below is "
            f"unfiltered: {why}",
        ))

    seen: set[str] = set()
    for probe in _PROBES:
        target = origin + probe.path
        resp, why = await _get(http, target)
        if why is not None:
            result.problems.append(ExposedProblem(target, "probe-failed", why))
            continue
        if resp.status_code != 200:
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
        result.findings.append(Finding(
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
    return result
