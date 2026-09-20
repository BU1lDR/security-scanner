import asyncio
import html
from urllib.parse import parse_qsl

import httpx

from scanner.core.egress import Egress
from scanner.core.finding import FRAGMENT_MAX_LEN, Confidence, Severity
from scanner.core.gate import RequestGate
from scanner.core.http import AsyncHttpClient
from scanner.core.rule_id import is_valid
from scanner.core.scope import Scope
from scanner.scanners.dast_active.checks import (
    check_open_redirect,
    check_sqli_error,
    check_xss_reflected,
)
from scanner.scanners.dast_active.injection import InjectionPoint


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def _point(param="q", value="hi", where="query", method="GET",
           url="https://example.com/search", extra=()):
    base = ((param, value),) + tuple(extra)
    return InjectionPoint(method, url, param, base, where)


def _run(coro):
    return asyncio.run(coro)


# --- reflected XSS -----------------------------------------------------------

class _EchoHttp:
    """Echoes the injected parameter into an HTML page, optionally HTML-escaped."""

    def __init__(self, escape=False, reflect=True):
        self.escape = escape
        self.reflect = reflect
        self.requests = []

    async def get(self, url, *, active=False, params=None, **kwargs):
        self.requests.append({"url": url, "active": active, "params": dict(params or [])})
        val = dict(params or []).get("q", "")
        if not self.reflect:
            return _Resp("<html>static page</html>")
        body = html.escape(val) if self.escape else val
        return _Resp(f"<html><body>results for {body}</body></html>")


def test_reflected_xss_is_detected_when_probe_comes_back_unescaped():
    http = _EchoHttp(escape=False)
    findings = _run(check_xss_reflected(_point(), http))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "dast.active.xss-reflected"
    assert is_valid(f.rule_id)
    assert f.scanner == "dast-active"
    assert f.severity is Severity.HIGH
    assert f.location.param == "q"
    assert f.fix is None
    assert http.requests[0]["active"] is True  # went through the active gate


def test_no_xss_when_probe_is_escaped():
    assert _run(check_xss_reflected(_point(), _EchoHttp(escape=True))) == []


def test_no_xss_when_probe_is_not_reflected():
    assert _run(check_xss_reflected(_point(), _EchoHttp(reflect=False))) == []


# --- error-based SQLi --------------------------------------------------------

class _SqlHttp:
    """Emits a database error string; ``always`` mimics a page that shows one
    regardless of input (to prove the baseline comparison suppresses it)."""

    _ERROR = "Warning: You have an error in your SQL syntax near ''' at line 1"

    def __init__(self, always=False):
        self.always = always
        self.requests = []

    async def get(self, url, *, active=False, params=None, **kwargs):
        val = dict(params or []).get("q", "")
        self.requests.append({"active": active, "value": val})
        if self.always or "'" in val:
            return _Resp(f"<html>{self._ERROR}</html>")
        return _Resp("<html>normal results</html>")


def test_sqli_error_is_detected_when_a_quote_triggers_a_db_error():
    http = _SqlHttp()
    findings = _run(check_sqli_error(_point(), http))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "dast.active.sqli-error"
    assert f.severity is Severity.HIGH
    assert f.scanner == "dast-active"
    assert f.location.param == "q"
    assert any(r["active"] for r in http.requests)


def test_no_sqli_when_error_string_is_present_in_baseline_too():
    # The page always shows the error text, so our quote adds nothing.
    assert _run(check_sqli_error(_point(), _SqlHttp(always=True))) == []


class _LeakySqlHttp:
    """A debug page that prints the failing query alongside the error — common
    on the misconfigured apps this check fires against."""

    _ERROR = (
        "PostgreSQL query failed: SELECT * FROM users WHERE email = "
        "'alice@example.com' AND token = 'sk-live-abc123def456' -- ERROR: "
        "syntax error at or near \"'\""
    )

    async def get(self, url, *, active=False, params=None, **kwargs):
        val = dict(params or []).get("q", "")
        if "'" in val:
            return _Resp(f"<html>{self._ERROR}</html>")
        return _Resp("<html>normal results</html>")


def test_sqli_evidence_names_the_error_family_without_echoing_the_response():
    """``Finding.evidence`` is contracted to be redacted at construction, but the
    check used to embed the regex match verbatim — and one pattern
    (``PostgreSQL.*ERROR``) is greedy, so it swallowed the whole line. A debug
    page echoing its failing query therefore put that query's data into the
    finding, and from there into report files on disk and the request body of an
    ``--ai`` call. The 500-char truncation bounds the size but not the leak: the
    first 500 chars are exactly where the query and its parameters are.

    The user needs to know *which* database's error appeared to triage the
    finding. They do not need the target's bytes to learn that."""
    findings = _run(check_sqli_error(_point(), _LeakySqlHttp()))

    assert len(findings) == 1
    evidence = findings[0].evidence
    # Nothing lifted out of the response body.
    for secret in ("alice@example.com", "sk-live-abc123def456", "SELECT", "users"):
        assert secret not in evidence, f"evidence leaked {secret!r}: {evidence!r}"
    # But still says which engine complained, so the finding is triageable.
    assert "PostgreSQL" in evidence


# --- open redirect -----------------------------------------------------------

class _RedirectHttp:
    """302s to whatever URL the parameter holds, if it looks like a URL."""

    def __init__(self, reflect=True):
        self.reflect = reflect
        self.requests = []

    async def get(self, url, *, active=False, params=None, **kwargs):
        val = dict(params or []).get("next", "")
        self.requests.append({"active": active, "value": val})
        if self.reflect and val.startswith("http"):
            return _Resp("", status_code=302, headers={"location": val})
        return _Resp("ok", status_code=200)


def test_open_redirect_is_detected_when_our_host_lands_in_location():
    http = _RedirectHttp()
    findings = _run(check_open_redirect(_point(param="next", value="/home"), http))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "dast.active.open-redirect"
    assert f.severity is Severity.MEDIUM
    assert f.scanner == "dast-active"
    assert f.location.param == "next"
    assert any(r["active"] for r in http.requests)


def test_no_open_redirect_when_server_does_not_redirect():
    assert _run(check_open_redirect(_point(param="next", value="/home"),
                                    _RedirectHttp(reflect=False))) == []


def test_open_redirect_skips_params_that_are_not_url_like():
    http = _RedirectHttp()
    findings = _run(check_open_redirect(_point(param="q", value="hi"), http))
    assert findings == []
    assert http.requests == []  # never even sent a probe for a non-URL param


# --- the body probe actually reaches the wire --------------------------------
# Every double above is hand-rolled, so none of them exercise httpx's own
# encoding rules -- which is how a real bug shipped. `_send` passed `data=` a
# list of pairs; httpx only form-encodes `data=` when it is a Mapping, so it fell
# through to raw-content encoding, built a *sync* byte stream, and AsyncClient
# refused it outright. `_send` swallows exceptions, so every body probe silently
# no-opped: the active tier reported a clean bill of health on POST forms it had
# never actually tested. A stub with `async def post(..., data=None)` cannot
# catch that, because the shape it accepts is the broken one.
#
# So this drives the real AsyncHttpClient and fakes only the socket.


def _real_client(handler):
    """A real client and a real gate; httpx.MockTransport stands in for the
    network so the request is genuinely built and encoded."""
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"},
        authorized_ack=True,
    )
    return AsyncHttpClient(
        RequestGate(scope=scope, egress=Egress()),
        user_agent="secscan-test/1.0",
        per_host_rps=1000.0,          # keep the token bucket out of the way
        transport=httpx.MockTransport(handler),
    )


def _body_point(param="comment", base=(("csrfmiddlewaretoken", "tok"), ("comment", "hi"))):
    return InjectionPoint("POST", "https://example.com/comment", param, base, "body")


def test_body_probe_is_form_encoded_and_reaches_the_transport():
    seen = []

    def handler(request):
        body = request.content.decode()
        seen.append({
            "method": request.method,
            "content_type": request.headers.get("content-type"),
            "body": body,
        })
        reflected = dict(parse_qsl(body, keep_blank_values=True)).get("comment", "")
        return httpx.Response(200, html=f"<html><body>{reflected}</body></html>")

    async def go():
        async with _real_client(handler) as http:
            return await check_xss_reflected(_body_point(), http)

    findings = _run(go())

    assert len(seen) == 1, "the body probe never reached the transport"
    assert seen[0]["method"] == "POST"
    assert seen[0]["content_type"] == "application/x-www-form-urlencoded"
    # Untampered fields keep their captured values, so CSRF-protected forms still
    # validate and the probe reaches the handler instead of a 403.
    assert "csrfmiddlewaretoken=tok" in seen[0]["body"]
    assert len(findings) == 1
    assert findings[0].rule_id == "dast.active.xss-reflected"
    assert findings[0].location.param == "comment"


def test_body_probe_keeps_duplicate_field_names():
    seen = []

    def handler(request):
        seen.append(request.content.decode())
        return httpx.Response(200, html="<html>static</html>")

    async def go():
        async with _real_client(handler) as http:
            point = _body_point(param="topic", base=(("topic", "a"), ("topic", "b")))
            return await check_xss_reflected(point, http)

    _run(go())

    assert len(seen) == 1
    # Both fields survive. dict(params) would have collapsed a checkbox group to
    # a single pair and quietly changed the request being tested.
    assert len(parse_qsl(seen[0], keep_blank_values=True)) == 2


def test_a_hostile_parameter_name_is_bounded_in_the_location():
    """The parameter name is the target's: the crawler read it out of the target's
    own HTML. The *request* must use it verbatim — a truncated name is a different
    parameter — but nothing downstream of ``Location`` caps what the report and the
    AI prompt carry, so the bound belongs here (D52)."""
    hostile = "p" * 4000
    sent = []

    class _Echo:
        async def get(self, url, *, active=False, params=None, **kwargs):
            sent.append(dict(params or []))
            return _Resp(f"<html><body>{dict(params or []).get(hostile, '')}</body></html>")

    findings = _run(check_xss_reflected(_point(param=hostile), _Echo()))

    assert len(findings) == 1
    assert hostile in sent[0], "the probe must be sent under the real parameter name"
    assert len(findings[0].location.param) <= FRAGMENT_MAX_LEN

    # Not just the location. The evidence interpolates the name too, and bounding
    # only at Location left that to the EVIDENCE_MAX_LEN cap — which the name then
    # consumed whole, truncating away the clause that says what was found. The
    # sentence after the name must survive.
    assert "reflected into the response" in findings[0].evidence
