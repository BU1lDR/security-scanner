"""The active checks (``dast.active.*``) — intrusive but *detection-only*.

Each check takes one :class:`~scanner.scanners.dast_active.injection.InjectionPoint`
and the shared HTTP client, sends a small number of crafted requests through the
client with ``active=True`` (so the choke point re-applies the triple gate), and
decides — from the response alone — whether the parameter is vulnerable. Every
request keeps all *other* parameters at their captured values so the app still
routes/validates the request.

The payloads are deliberately the minimum needed to *observe* a flaw, never to
exploit one (decisions.md D8):

- **reflected XSS** — a benign non-executing marker with HTML metacharacters; a
  finding is raised only if it comes back *unescaped* (the encoding boundary is
  broken). We never send a working script/event-handler payload.
- **error-based SQLi** — a single quote appended to the value. A finding is raised
  only if it produces a database error string that a *baseline* (untampered)
  request did not — no boolean/time-based probing, no ``OR 1=1``, no data access.
- **open redirect** — a benign external sentinel URL placed in URL-shaped
  parameters; a finding is raised only if the server 3xx-redirects to that host.

Findings carry ``fix=None``: a live app has no file for us to patch (contract §7).
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlsplit

from scanner.core.finding import FRAGMENT_MAX_LEN, Confidence, Finding, Severity, bounded
from scanner.core.location import Location

_WSTG = "https://owasp.org/www-project-web-security-testing-guide/"

# --- reflected XSS -----------------------------------------------------------
# A unique marker that cannot occur naturally; the angle-bracket form is what we
# look for, so an HTML-escaped reflection (&lt;marker&gt;) is correctly ignored.
_XSS_MARKER = "sxqz91kv7"
_XSS_PROBE = f'{_XSS_MARKER}"><{_XSS_MARKER}>'
_XSS_SIGNATURE = f"<{_XSS_MARKER}>"

# --- error-based SQLi --------------------------------------------------------
_SQLI_PROBE = "'"

# Signatures grouped by database engine, so a finding can say *which* engine
# complained without quoting the response back.
#
# The grouping is a redaction measure, not cosmetics. `Finding.evidence` must be
# redacted at construction, and echoing the matched text cannot satisfy that: the
# pages this check fires on are precisely the ones that print their failing query,
# so the match may carry that query's own data — an email, a session id, an API
# token — into the report, and from there onto disk and into an `--ai` request.
# Some signatures are also unbounded (`PostgreSQL.*ERROR` spans a whole line), so
# truncation limits the size of such a leak without preventing it.
#
# Order matters: specific engines first, the generic signatures last.
_SQL_ERRORS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile("|".join(patterns), re.IGNORECASE))
    for label, patterns in (
        ("MySQL", [
            r"You have an error in your SQL syntax",
            r"check the manual that corresponds to your (?:MySQL|MariaDB)",
            r"MySqlException",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
        ]),
        ("PostgreSQL", [
            r"PostgreSQL.*ERROR",
            r"org\.postgresql\.util\.PSQLException",
            r"PG::(?:Syntax|Undefined|Grouping)Error",
            r"syntax error at or near",
            r"unterminated quoted string",
        ]),
        ("SQL Server", [
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"System\.Data\.SqlClient\.SqlException",
            r"com\.microsoft\.sqlserver\.jdbc",
        ]),
        ("Oracle", [
            r"ORA-[0-9]{5}",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
        ]),
        ("SQLite", [
            r"sqlite3?\.(?:Operational|Programming)Error",
            r"org\.sqlite\.JDBC",
            r"unrecognized token",
            r"SQL logic error",
        ]),
        ("generic SQL", [
            r"java\.sql\.SQLException",
            r"\[SQLSTATE\]|SQLSTATE\[",
        ]),
    )
)


def _sql_error_family(body: str) -> str | None:
    """Which database engine's error signature appears in ``body``, if any.

    Returns the engine's name and never a slice of ``body`` — that is the whole
    point of this helper (see the note above ``_SQL_ERRORS``).
    """
    for label, pattern in _SQL_ERRORS:
        if pattern.search(body):
            return label
    return None

# --- open redirect -----------------------------------------------------------
_REDIRECT_HINT = re.compile(
    r"(redirect|redir|url|uri|next|return|dest|destination|continue|goto|target|callback)",
    re.IGNORECASE,
)
_REDIRECT_SENTINEL_HOST = "example.org"  # IANA-reserved; harmless as a redirect target
_REDIRECT_PROBE = "https://example.org/secscan-open-redirect-probe"


def _original(point) -> str:
    for name, value in point.base_params:
        if name == point.param:
            return value
    return ""


def _params_with(point, value: str) -> list[tuple[str, str]]:
    return [(n, value if n == point.param else v) for n, v in point.base_params]


async def _send(http, point, value: str):
    """Send one probe. Failures propagate on purpose.

    This used to catch ``Exception`` and return ``None``, on the reasoning that a
    failed probe is not a finding. True, and not the whole question: a probe that
    never got an answer is not a *negative* either, and every check below reads a
    missing response as one — no marker came back, no database error appeared, no
    redirect was issued. So a timeout, a connection reset, a rate-limit refusal and
    a parameter that is genuinely safe all produced the same silence, and the report
    said the parameter had been tested.

    Nothing here needs a local handler. ``ScanContext.run_check`` wraps every
    (point, check) pair already, so the failure is recorded as a ``ScanError``, the
    remaining checks continue, and the scan exits 3 instead of 0 when that error is
    all there is. Fault isolation was always in place; this function was the one
    thing standing between the failure and it (D59).
    """
    params = _params_with(point, value)
    if point.where == "body":
        # Encode the body ourselves rather than passing the pairs to `data=`.
        # httpx only form-encodes `data=` when it is a Mapping; given a list
        # it falls back to raw-content encoding and builds a *sync* byte
        # stream, which AsyncClient then refuses outright. Hand-encoding also
        # keeps duplicate field names (checkbox groups), which dict() would
        # collapse.
        return await http.post(
            point.url,
            active=True,
            content=urlencode(params),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    return await http.get(point.url, active=True, params=params)


async def _baseline(http, point):
    return await _send(http, point, _original(point))


def _body(resp) -> str:
    return (getattr(resp, "text", "") or "") if resp is not None else ""


def _header(resp, name: str) -> str:
    if resp is None:
        return ""
    getter = getattr(resp.headers, "get", None)
    return (getter(name) or "") if callable(getter) else ""


def _name(point) -> str:
    """The target's parameter name, bounded for anything we *write*.

    The request uses ``point.param`` verbatim; every string that ends up in a
    report goes through here instead. This exists as a function because the
    evidence sentences are built by the callers below, before :func:`_finding`
    ever sees them — bounding only at ``Location`` left those relying on the
    ``EVIDENCE_MAX_LEN`` field cap, and a 4000-character name then consumed the
    whole budget and truncated away the clause that said what was wrong. Bounding
    the fragment is the right unit; the field cap is the backstop (D52).
    """
    return bounded(point.param, FRAGMENT_MAX_LEN) if point.param else point.param


def _finding(rule_id: str, title: str, severity: Severity, point, evidence: str,
             remediation: str, references: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        # The parameter name came from the target's own HTML. The request used it
        # verbatim; the *report* gets it bounded, because nothing downstream of
        # Location caps it — the fingerprint keys on location, so it cannot be
        # capped at the field (D52).
        location=Location.for_url(
            point.url, method=point.method, param=_name(point),
        ),
        evidence=evidence,  # Finding caps and scrubs it (EVIDENCE_MAX_LEN)
        remediation=remediation,
        scanner="dast-active",
        references=references,
        fix=None,
    )


async def check_xss_reflected(point, http) -> list[Finding]:
    resp = await _send(http, point, _XSS_PROBE)
    if _XSS_SIGNATURE not in _body(resp):
        return []
    return [
        _finding(
            "dast.active.xss-reflected",
            "Reflected cross-site scripting (unescaped input)",
            Severity.HIGH, point,
            f"The '{_name(point)}' parameter was reflected into the response "
            f"unescaped (our marker came back as {_XSS_SIGNATURE}), so HTML/script "
            "metacharacters are not being encoded.",
            "Context-sensitively encode all user input on output (HTML-escape by "
            "default) and add a Content-Security-Policy as defence in depth.",
            [_WSTG, "CWE-79"],
        )
    ]


async def check_sqli_error(point, http) -> list[Finding]:
    baseline = await _baseline(http, point)
    if _sql_error_family(_body(baseline)):
        return []  # page emits a DB error regardless of input; can't attribute it
    resp = await _send(http, point, _original(point) + _SQLI_PROBE)
    family = _sql_error_family(_body(resp))
    if not family:
        return []
    return [
        _finding(
            "dast.active.sqli-error",
            "SQL injection (database error triggered)",
            Severity.HIGH, point,
            f"Appending a single quote to '{_name(point)}' produced a {family} "
            "database error that the untampered request did not, indicating the "
            "value reaches an SQL query unsanitized.",
            "Use parameterized queries / prepared statements; never build SQL by "
            "string concatenation. Validate and least-privilege the DB account.",
            [_WSTG, "CWE-89"],
        )
    ]


def _looks_url_ish(point) -> bool:
    if _REDIRECT_HINT.search(point.param):
        return True
    return _original(point).startswith(("http://", "https://", "//", "/"))


async def check_open_redirect(point, http) -> list[Finding]:
    if not _looks_url_ish(point):
        return []
    resp = await _send(http, point, _REDIRECT_PROBE)
    status = getattr(resp, "status_code", 0)
    if not (300 <= status < 400):
        return []
    location = _header(resp, "location")
    if not location or urlsplit(location).hostname != _REDIRECT_SENTINEL_HOST:
        return []
    return [
        _finding(
            "dast.active.open-redirect",
            "Open redirect (attacker-controlled redirect target)",
            Severity.MEDIUM, point,
            f"Setting '{_name(point)}' to an external URL caused a {status} redirect "
            f"to that host ({_REDIRECT_SENTINEL_HOST}), so the redirect target is "
            "user-controlled.",
            "Do not redirect to raw user input. Allowlist permitted targets or use "
            "opaque server-side keys that map to fixed destinations.",
            [_WSTG, "CWE-601"],
        )
    ]


# The active-tier checks, in the order the scanner runs them.
ALL_CHECKS = {
    "xss-reflected": check_xss_reflected,
    "sqli-error": check_sqli_error,
    "open-redirect": check_open_redirect,
}
