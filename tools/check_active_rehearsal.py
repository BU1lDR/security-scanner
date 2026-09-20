"""Aim the active tier at a deliberately-flawed loopback site and read the wire.

The active tier had already run live twice before this file existed: D43 against a
flawed server on ``127.0.0.1`` with a 33-request wire capture, and D51 against
PyGoat, which is where the silently-empty POST body was caught. Neither run could
be repeated. Both harnesses lived on one machine and never landed in the
repository, so what the project could demonstrate on demand was nothing at all --
``--active`` appeared in no workflow and no tool, and the one end-to-end gate,
``check_self_scan.py``, scans ``./src``: a *code* target, so it never starts the
DAST path, passive included.

So the gap was never "the active tier has not been verified". It was "nothing
re-verifies it", which for the one tier whose entire risk is that it sends
attack-shaped traffic at somebody else's server is the worse of the two. A live
run that is not repeatable expires: it describes a tree that has since moved.

**Matched pairs, from D43.** Every check gets two routes -- one genuinely flawed,
one with the flaw's guard in place -- and the assertion is exact set equality over
``(rule_id, path, method, param)``, so a false negative and a false positive fail
the same assertion. A target containing only flaws proves the checks fire, not
that they are right:

===================  =====================================  ========================
route                planted                                must report
===================  =====================================  ========================
``/reflect``         reflects ``q`` unescaped               ``xss-reflected``
``/reflect-safe``    the same, HTML-escaped                 nothing
``/find``            reflects a *form's* GET parameter       ``xss-reflected``
``/report``          PostgreSQL error only when ``'`` present  ``sqli-error``
``/report-broken``   MySQL error regardless of input        nothing (unattributable)
``/go``              honours ``next`` as a 302              ``open-redirect``
``/go-fixed``        302s to a fixed internal path          nothing (host guard)
``/go-200``          200 *plus* a ``Location`` header       nothing (status guard)
``/long``            reflects a 4000-char *parameter name*  ``xss-reflected`` (D52)
``/comment``         reflects a POST body field             ``xss-reflected`` (D51)
===================  =====================================  ========================

``/go-200`` is why this file was rewritten. D56 shipped eight mutations, each of
which reddened the assertion written for it; re-running them found that deleting
the open-redirect **3xx status** test changed nothing, because the only guarded
redirect route returned a real 302 and the hostname test alone accounted for the
negative. A guard whose removal keeps the gate green is the gate's own false
negative. 200-with-a-``Location`` is an ordinary framework shape and makes that
guard observable (D57).

**Read the wire, not the exit code.** Every trap that makes this kind of
rehearsal vacuous ends in a clean-looking exit 0: the crawler needs the literal
substring ``html`` in ``Content-Type`` and Python's ``BaseHTTPRequestHandler``
does not send one for you; ``crawler._get`` swallows every exception and returns
``None``, so connection-refused and a timed-out fetch leave no record; a redirect
on the entry path empties the crawl. Asserting ``exit == 1`` would pass while the
scanner never reached the site. So the server keeps its own log of every request
it receives -- time, method, full untruncated path, full body, ``Host``,
``User-Agent``, ``Content-Type``, the status we answered with -- and the
assertions are made against that. It is an independent witness: the scanner runs
as a subprocess, so nothing it believes about itself can reach this log.

**Every list-driven assertion names its expected length first.** D56's D52 block
looped over a list of findings and ran zero assertions when the list was empty --
a PASS whose meaning was "there was no finding to check". That is the one shape
this file exists to refuse, so counts are asserted before loops throughout.

**Five phases.** Authorized; authorization withheld; a four-request budget; a
socket bound but never listened on (which must exit 3, not 0); and one
in-process phase for the ``dast.active.enabled`` guard that argv cannot reach.
The in-process phase runs its *positive* control first, because D43's first
harness reported PASS on eight gate cases while the scanner registry was empty.

**Two listeners.** ``127.0.0.1`` is the target. ``127.0.0.2`` is in
``scope.allowed_hosts`` and *not* in the active allowlist, so the crawl reads it
and no probe may reach it -- the witness for the per-request ``active=True`` gate,
taken from the CLI rather than from a unit test. Linux and Windows bind all of
127/8; a macOS contributor needs ``sudo ifconfig lo0 alias 127.0.0.2 up``. If the
bind fails this file fails loudly: a silent skip is the vacuity it exists to
prevent.

Usage::

    python tools/check_active_rehearsal.py

Loopback only, and no non-loopback network. The open-redirect probe names
``example.org`` in a *parameter value*; the request itself goes to an ephemeral
loopback port, and ``core/http.py`` builds its client with
``follow_redirects=False``, so the 302 this site returns is read and never
followed. The assertions check that the only hosts contacted were the two
loopback ones.
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent

# How long the scan gets before we call it wedged. A hung fetch must fail loudly
# rather than burn the job's six-hour ceiling; crawler._get would otherwise sit
# out its timeout on every page with nothing recorded anywhere.
SCAN_TIMEOUT_S = 240

# The probe strings the active tier uses, duplicated here on purpose. Importing
# them from scanner.scanners.dast_active.checks would make this file agree with
# the code by construction: if a rename broke the probe, both sides would move
# together and the assertion would still pass. These are pinned copies, so a
# change to either has to be made deliberately in two places. (The cost is
# stated rather than hidden: a coordinated two-sided rename is invisible here,
# and tests/test_dast_active_checks.py owns the constants' values.)
XSS_MARKER = "sxqz91kv7"
XSS_SIGNATURE = f"<{XSS_MARKER}>"
REDIRECT_PROBE_PATH = "secscan-open-redirect-probe"
REDIRECT_SENTINEL_HOST = "example.org"

# A parameter name chosen by the *target*, long enough to exercise D52's bounding
# on data that arrived over the network rather than from a fixture. Deliberately
# free of any substring in the open-redirect hint list, so only the XSS check
# fires on this route and the attribution stays unambiguous. 4000 and not more:
# BaseHTTPRequestHandler answers 414 past ~65k, and a 414 deletes the page from
# the crawl, which would turn a D52 assertion into a route-availability one.
LONG_NAME = "n" + "A" * 3999

# What D52's bounding must turn that into: FRAGMENT_MAX_LEN is 120 and the
# truncation marker is 15 characters, so 105 characters of name survive. Pinned,
# not computed from the source, for the same reason the probes are.
BOUNDED_LONG_NAME = "n" + "A" * 104 + "... (truncated)"

# A cookie name the *target* chose that matches redaction.GITHUB_TOKEN
# (ghp_ + 36 alphanumerics). scrub() runs on it inside the passive cookie check,
# so the report must carry the masked form and never the raw one. A token-shaped
# *name* rather than a token-shaped value in the SQL error, because scrub()
# masking a canary would hand back a false pass on the non-leakage assertion.
COOKIE_NAME = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
COOKIE_REDACTED = "ghp_" + "*" * 36

# Shapeless strings planted in /report's database error. They are what a real
# error page leaks -- a row's own data and the failing query -- and no redaction
# layer can recognise them, so their absence from the report is a real result
# rather than an artefact of scrub() having masked them (D44, D57).
CANARIES = ("alice@example.com", "SELECT id", "FROM users")

# Matches checks.py's MySQL group ("You have an error in your SQL syntax").
MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near ''' at line 1"
)

# Matches checks.py's PostgreSQL group, whose first pattern (PostgreSQL.*ERROR)
# is the unbounded one -- it spans a line, so it is the signature whose match
# could carry the most of somebody else's data into a report. Carries all three
# canaries.
POSTGRES_ERROR = (
    "PostgreSQL ERROR: unterminated quoted string at or near \"'\"\n"
    "LINE 1: SELECT id, email FROM users WHERE name = 'alice''\n"
    "Detail: the row belonged to alice@example.com\n"
)

# Exploitation shapes the payloads must never contain (D8: detection-only). The
# XSS marker is an inert unknown tag and the SQLi probe is one quote; anything
# below would mean the tier had started trying to *use* a flaw instead of observe
# it. Checked against the percent-decoded path and body of every request.
FORBIDDEN = (
    "or 1=1", "union", "sleep(", "waitfor", "benchmark(", "drop table",
    "xp_cmdshell", "<script", "onerror=", "onload=", "onfocus=", "javascript:",
    "../", "..%2f", "%00", "etc/passwd", "--", "/*",
)

# The shape of an honest agent string: name/version plus a contact URL. A scanner
# that disguises itself as a browser is a different tool with a different consent
# story, so the assertion is on the shape and not merely on "one distinct value".
UA_SHAPE = re.compile(r"^secscan/\d+\.\d+\.\d+ \(\+https://\S+\)$")


# --------------------------------------------------------------------------- #
# the site
# --------------------------------------------------------------------------- #

#: Filled in once both listeners are up; the index page has to link to the
#: second listener's ephemeral port.
SITE: dict[str, int] = {"p1": 0, "p2": 0}


def index_page() -> str:
    """The entry page. Links every route the crawl is meant to reach, including
    one on the second loopback address -- in scope for the crawl, absent from the
    active allowlist. ``/find`` is deliberately *not* linked: it is reachable only
    through the GET form on ``/forms``, so it also proves the form path produces
    query injection points and not only body ones."""
    return f"""<!doctype html>
<html><body><h1>rehearsal target</h1>
<a href="/forms">forms</a>
<a href="/home">home</a>
<a href="/guard">guard</a>
<a href="/reflect?q=hello">reflect</a>
<a href="/reflect-safe?q=hello">reflect-safe</a>
<a href="/report?name=alice">report</a>
<a href="/report-broken?name=alice">report-broken</a>
<a href="/go?next=/home">go</a>
<a href="/go-fixed?next=/home">go-fixed</a>
<a href="/go-200?next=/home">go-200</a>
<a href="/long?{LONG_NAME}=x">long</a>
<a href="http://127.0.0.2:{SITE['p2']}/cross?q=hi">cross</a>
</body></html>"""


# Two forms. The GET one becomes a query injection point on a route no link
# reaches. The POST one carries, beside the two targeted text fields: a hidden
# CSRF token (preserved, never targeted -- the property that makes a body probe
# reach the application instead of bouncing off its CSRF check), a checkbox pair
# sharing one name (preserved at *both* values, which dict(params) would
# collapse), and a submit button (a non-target type).
FORMS_PAGE = """<!doctype html>
<html><body>
<form method="GET" action="/find">
<input type="text" name="term" value="widget">
</form>
<form method="POST" action="/comment">
<input type="hidden" name="csrfmiddlewaretoken" value="rehearsal-token">
<input type="text" name="author" value="anon">
<input type="text" name="comment" value="hi">
<input type="checkbox" name="tags" value="a">
<input type="checkbox" name="tags" value="b">
<input type="submit" name="post" value="Post">
</form>
</body></html>"""


class Wire:
    """The server's own record of what it was sent. The independent witness."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: list[dict] = []

    def begin(self, record: dict) -> dict:
        with self._lock:
            # Appended on arrival and completed in the handler's finally:, so a
            # handler that raises still leaves a record. Untruncated,
            # deliberately -- a log that shortens what it stores cannot answer
            # the question this gate exists to answer, and a 4000-character
            # parameter name is exactly what a truncating log hides.
            # BaseHTTPRequestHandler.log_message truncates; it is silenced below.
            self.requests.append(record)
        return record

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self.requests)

    def clear(self) -> None:
        with self._lock:
            self.requests.clear()


WIRE = Wire()


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 with an explicit Content-Length on every response. Setting the
    # version without the header makes httpx wait out its read timeout on every
    # single fetch, and crawler._get swallows the timeout -- a clean report over
    # a site that was never read.
    protocol_version = "HTTP/1.1"
    server_version = "rehearsal"
    sys_version = ""

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        pass  # superseded by Wire, which does not truncate

    # -- plumbing ----------------------------------------------------------- #
    def _begin(self, method: str, body: str) -> dict:
        self._status = 0
        self._location = ""
        return WIRE.begin({
            "t": time.monotonic(),
            "method": method,
            "path": self.path,
            "body": body,
            "host": self.headers.get("host", "") or "",
            "ua": self.headers.get("user-agent", "") or "",
            "ctype": self.headers.get("content-type", "") or "",
            "status": 0,
            "location": "",
        })

    def _send(self, status: int, body: bytes = b"",
              extra: dict[str, str] | None = None) -> None:
        self._status = status
        self._location = (extra or {}).get("Location", "")
        self.send_response(status)
        # Always present, always containing "html": crawler._is_html looks for
        # that literal substring and skips link and form extraction without it,
        # which yields zero injection points and a healthy-looking empty result.
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    @staticmethod
    def _page(inner: str) -> bytes:
        return f"<!doctype html><html><body>{inner}</body></html>".encode()

    # -- routes ------------------------------------------------------------- #
    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        record = self._begin("GET", "")
        try:
            self._route_get()
        finally:
            record["status"] = self._status
            record["location"] = self._location

    def _route_get(self) -> None:
        parts = urlsplit(self.path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        path = parts.path

        if path == "/":
            # A token-shaped cookie *name*, chosen by the target, so scrub()
            # runs on live text rather than on a fixture. SameSite is present
            # and Secure is not applicable over http, so exactly one cookie
            # finding is produced and its param is the masked name.
            return self._send(200, index_page().encode(), extra={
                "Set-Cookie": f"{COOKIE_NAME}=1; SameSite=Lax; Path=/",
            })
        if path == "/forms":
            return self._send(200, FORMS_PAGE.encode())
        if path == "/home":
            return self._send(200, self._page("<p>home</p>"))
        if path == "/guard":
            # The in-process phase's entry point: one link, one parameter, so
            # that phase costs five requests instead of fifty.
            return self._send(200, self._page(
                '<a href="/reflect?q=hello">reflect</a>'))

        # XSS trio -----------------------------------------------------------
        if path == "/reflect":
            return self._send(200, self._page(
                f"<p>results for {query.get('q', '')}</p>"))
        if path == "/reflect-safe":
            return self._send(200, self._page(
                f"<p>results for {html.escape(query.get('q', ''))}</p>"))
        if path == "/find":
            # Same flaw as /reflect, reached only through the GET form.
            return self._send(200, self._page(
                f"<p>matches for {query.get('term', '')}</p>"))

        # SQLi pair. Neither route reflects its input: the XSS check runs here
        # too, and a reflection would raise a second finding on these routes and
        # blur which check the pair is actually testing.
        if path == "/report":
            if "'" in query.get("name", ""):
                # Shapeless canaries, in a <pre>, on the one signature that is
                # unbounded. Nothing downstream can mask these, so their absence
                # from the report means the check really does not quote bodies.
                return self._send(200, self._page(
                    f"<pre>{POSTGRES_ERROR}</pre>"))
            return self._send(200, self._page("<p>no such user</p>"))
        if path == "/report-broken":
            # Errors whatever it is sent, so the baseline request already carries
            # the signature and checks.py refuses to attribute it to the input.
            # A different engine from /report, so the pair differs by engine as
            # well as by guard.
            return self._send(200, self._page(f"<p>{MYSQL_ERROR}</p>"))

        # open-redirect trio -------------------------------------------------
        if path == "/go":
            nxt = query.get("next", "")
            if nxt.startswith(("/", "http://", "https://")):
                return self._send(302, b"", extra={"Location": nxt})
            # The 200 branch must not echo `next`: an XSS finding here would put
            # /go in two matched pairs at once.
            return self._send(200, self._page("<p>stay here</p>"))
        if path == "/go-fixed":
            # A real 3xx that ignores the parameter. Exercises the check's
            # hostname test: the status passes and the Location host is not the
            # sentinel, so there is no finding.
            return self._send(302, b"", extra={"Location": "/home"})
        if path == "/go-200":
            # A 200 that *also* carries Location -- the shape frameworks produce
            # when a handler sets the header and forgets the status. Exercises
            # the check's 3xx status test, which nothing else here can falsify.
            return self._send(200, self._page("<p>redirecting</p>"),
                              extra={"Location": query.get("next", "")})

        # D52: a 4000-character parameter name, chosen by the target ----------
        if path == "/long":
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                if len(name) > 100:
                    return self._send(200, self._page(f"<p>echo {value}</p>"))
            return self._send(200, self._page("<p>nothing</p>"))

        # the second listener ------------------------------------------------
        if path == "/cross":
            # The same flaw as /reflect. Nothing here may ever be reached by a
            # probe: this host is in scope and not in the active allowlist.
            return self._send(200, self._page(
                f"<p>results for {query.get('q', '')}</p>"))

        # Matches no dast.exposed signature, so the five calibration/.env/.git
        # GETs produce nothing.
        return self._send(404, self._page("<p>not found</p>"))

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        record = self._begin("POST", raw)
        try:
            self._route_post(raw)
        finally:
            record["status"] = self._status
            record["location"] = self._location

    def _route_post(self, raw: str) -> None:
        if urlsplit(self.path).path != "/comment":
            return self._send(404, self._page("<p>not found</p>"))

        # Three gates a real application would have, so a malformed probe
        # cannot be mistaken for an accepted one. Without them a probe that
        # dropped the content-type header, collapsed the checkbox pair, or lost
        # the CSRF sibling would still get a 200 and still look fine on the
        # wire.
        ctype = (self.headers.get("content-type") or "").lower()
        if not ctype.startswith("application/x-www-form-urlencoded"):
            return self._send(415, self._page("<p>unsupported media type</p>"))

        pairs = parse_qsl(raw, keep_blank_values=True)
        fields = dict(pairs)
        if fields.get("csrfmiddlewaretoken") != "rehearsal-token":
            return self._send(403, self._page("<p>csrf check failed</p>"))
        if len([v for n, v in pairs if n == "tags"]) != 2:
            return self._send(400, self._page("<p>bad tags</p>"))

        author = fields.get("author", "")
        if "'" in author:
            return self._send(200, self._page(f"<p>{MYSQL_ERROR}</p>"))
        return self._send(200, self._page(
            f"<p>by {html.escape(author)}</p>"
            f"<div>{fields.get('comment', '')}</div>"))


def start_site(host: str) -> tuple[ThreadingHTTPServer, int]:
    """Bind ``host`` on an ephemeral port, and do not return until it accepts.

    Port 0 rather than a fixed number so concurrent CI jobs on one runner cannot
    collide. The accept-poll closes the race the traps section names: if secscan
    starts first, every fetch is refused, crawler._get returns None for each, and
    the scan reports a clean site it never reached.
    """
    srv = ThreadingHTTPServer((host, 0), Handler)
    srv.daemon_threads = True  # so shutdown cannot hang CI on a live connection
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    for _ in range(100):
        with socket.socket() as probe:
            probe.settimeout(0.25)
            if probe.connect_ex((host, port)) == 0:
                return srv, port
        time.sleep(0.02)
    raise RuntimeError(f"the rehearsal site never accepted on {host}:{port}")


# --------------------------------------------------------------------------- #
# running the scanner
# --------------------------------------------------------------------------- #

def command() -> list[str]:
    """The installed console script if there is one, else the module.

    Same reasoning as check_self_scan.py: an entry point can be misdeclared in
    pyproject.toml while every unit test still passes.
    """
    found = shutil.which("secscan")
    return [found] if found else [sys.executable, "-m", "scanner.cli"]


# Phases A, B and D. include_post has no CLI flag, so without this file the body
# path -- the exact code path whose silently-empty POST shipped (D51) -- is
# unreachable from argv and the rehearsal would quietly test only query
# parameters. allowed_hosts adds the second listener to the *crawl* boundary
# without adding it to the active allowlist, which only the typed target host
# joins. per_host_rps is low enough that the token bucket is measurable: 8 rps
# over ~56 requests costs about six seconds and buys an assertion that the
# limiter exists at all.
MAIN_CONFIG = """
[scope]
allowed_hosts = ["127.0.0.2"]

[dast.active]
include_post = true
max_requests = 200

[dast.crawler]
max_depth = 2
max_pages = 50

[http]
per_host_rps = 8.0
timeout_s = 10.0
"""

# Phase C. The budget, not the pacing, is what this config measures, so the rate
# goes back up and the scope/crawler sections are left at their defaults.
CAPPED_CONFIG = """
[dast.active]
include_post = true
max_requests = 4

[http]
per_host_rps = 25.0
timeout_s = 10.0
"""


def run_scan(url: str, config_path: Path, *, authorized: bool
             ) -> tuple[int, str, str]:
    args = [
        url, "--active",
        "--config", str(config_path), "--format", "json",
    ]
    if authorized:
        args.append("--i-am-authorized")

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(ROOT / "src"), env.get("PYTHONPATH", "")])
    )
    try:
        proc = subprocess.run(
            command() + args, cwd=ROOT, capture_output=True, text=True,
            env=env, timeout=SCAN_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return -1, "", f"the scan did not finish within {SCAN_TIMEOUT_S}s"
    return proc.returncode, proc.stdout, proc.stderr


def capture(url: str, config_path: Path, *, authorized: bool
            ) -> tuple[int, str, str, list[dict], float]:
    """One scan, with the wire slice that belongs to it and its wall clock."""
    WIRE.clear()
    started = time.monotonic()
    code, out, err = run_scan(url, config_path, authorized=authorized)
    wall = time.monotonic() - started
    return code, out, err, WIRE.snapshot(), wall


# --------------------------------------------------------------------------- #
# assertions
# --------------------------------------------------------------------------- #

class Checks:
    """Collects every failure instead of stopping at the first.

    A gate that reports one problem per run makes the person fixing it re-run to
    discover the next; the interesting information is usually the *pattern*
    across several assertions.
    """

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.total = 0

    def ok(self, message: str) -> None:
        self.total += 1
        print(f"  ok   {message}")

    def fail(self, message: str, *detail: str) -> None:
        self.total += 1
        print(f"  FAIL {message}")
        for line in detail:
            print(f"         {line}")
        self.failures.append(message)

    def expect(self, condition: bool, message: str, *detail: str) -> bool:
        if condition:
            self.ok(message)
        else:
            self.fail(message, *detail)
        return bool(condition)


#: The exact set of ``(rule_id, path, method, param)`` the active tier must
#: report. Set equality, so a false negative and a false positive fail the same
#: assertion -- and a check that has started firing on everything cannot hide
#: behind a per-route count.
EXPECTED: set[tuple[str, str, str, str]] = {
    ("dast.active.xss-reflected", "/reflect", "GET", "q"),
    ("dast.active.xss-reflected", "/find", "GET", "term"),
    ("dast.active.xss-reflected", "/long", "GET", BOUNDED_LONG_NAME),
    ("dast.active.xss-reflected", "/comment", "POST", "comment"),
    ("dast.active.sqli-error", "/report", "GET", "name"),
    ("dast.active.sqli-error", "/comment", "POST", "author"),
    ("dast.active.open-redirect", "/go", "GET", "next"),
}

#: Arithmetic, not folklore: 13 injection points (9 query pages, 1 GET form
#: field, 3 POST body fields) minus the one on 127.0.0.2 that the request gate
#: refuses. One XSS probe per point carries the marker; the SQLi probe carries a
#: quote and the redirect probe a URL, so neither is counted here. Adding a
#: fourth active check or a URL-ish parameter should redden this -- that is the
#: gate asking to be updated, not flaking.
EXPECTED_PROBES = 12

#: 3 body injection points x (1 XSS request + 2 SQLi requests: baseline, probe).
#: The open-redirect check sends nothing on these three: none of the names hints
#: at a URL and none of the captured values looks like one.
EXPECTED_POSTS = 9

#: The three routes the open-redirect sentinel must be attempted against, so
#: both of that check's guards are exercised and not merely reached.
REDIRECT_ROUTES = {"/go", "/go-fixed", "/go-200"}

#: Phase A's rate, repeated here because the floor is arithmetic from it.
PHASE_A_RPS = 8.0

#: Phase E's enabled run, counted the same way: ``/guard`` links to one page with
#: one parameter, so 1 injection point x (1 XSS + 2 SQLi) = 3 active requests. The
#: open-redirect check sends nothing -- ``q`` does not hint at a URL and ``hello``
#: does not look like one. The two crawl GETs are passive and are not counted, which
#: is the distinction this number exists to hold the report to.
EXPECTED_GUARD_ACTIVE_REQUESTS = 3


def decoded(record: dict) -> str:
    return unquote(record["path"]) + " " + unquote(record["body"])


def tags_of(record: dict) -> list[str]:
    return [v for n, v in parse_qsl(record["body"], keep_blank_values=True)
            if n == "tags"]


def four_tuple(finding: dict) -> tuple[str, str, str, str]:
    location = finding.get("location") or {}
    return (
        finding.get("rule_id") or "?",
        urlsplit(location.get("url") or "").path,
        location.get("method") or "",
        location.get("param") or "",
    )


def pacing_floor(n: int, rps: float) -> float:
    """The shortest span ``n`` paced requests can legitimately take.

    One-directional on purpose: a burst plus scheduler noise makes "no faster
    than rps" the flaky direction, so only the floor is asserted and a slow
    runner can only make it safer. The free burst is subtracted because
    TokenBucket's capacity is ``max(1.0, rate)`` -- the first ``rate`` requests
    cost no time at all -- and the remaining half is margin.
    """
    return 0.5 * max(0.0, n - max(1.0, rps)) / rps


# --------------------------------------------------------------------------- #
# phase A -- authorized
# --------------------------------------------------------------------------- #

def phase_a(checks: Checks, url: str, config_path: Path,
            hosts: tuple[str, str]) -> int | None:
    """Returns phase A's marker count, or None if the hard bail tripped."""
    code, out, err, wire, wall = capture(url, config_path, authorized=True)
    print(f"  [{len(wire)} requests, wall {wall:.2f}s, exit {code}]")

    # -- A1: positive control, before any judgement about findings ----------- #
    # D43's harness reported PASS on every gate case while the registry was
    # empty and nothing had run at all. If nothing arrived, nothing below this
    # line carries information, so this returns rather than accumulating reds.
    if not checks.expect(
        bool(wire), "the site received requests",
        f"zero requests arrived; exit was {code}",
        "the scanner never reached the site, so nothing after this would mean "
        "anything -- bailing out rather than printing 41 vacuous passes",
        (err or "")[-400:],
    ):
        return None

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        checks.fail("the JSON report parses", out[-1200:], (err or "")[-400:])
        return None

    scan = report.get("scan") or {}
    findings = report.get("findings") or []
    active = [f for f in findings if f.get("scanner") == "dast-active"]

    # A2: _render_json omits "scan" entirely when nothing was recorded, which is
    # the signature of a run that selected no scanner.
    checks.expect("scan" in report, "the report carries a scan block",
                  f"top-level keys were {sorted(report)}")
    # A3
    checks.expect(
        (scan.get("scanners_run") or []) == ["dast", "dast-active"],
        "scanners_run == ['dast', 'dast-active']",
        f"scan block was {scan!r}",
    )
    # A4: D50's disclosure -- what the tool *did*, not what it found.
    checks.expect(
        scan.get("sent_active_traffic") is True,
        "the report discloses active traffic",
        f"sent_active_traffic was {scan.get('sent_active_traffic')!r}",
    )
    # A5: the positive control proper. Payloads left the process and arrived.
    probes = [r for r in wire if XSS_MARKER in decoded(r)]
    checks.expect(
        len(probes) == EXPECTED_PROBES,
        f"probes on the wire ({len(probes)}/{len(wire)})",
        f"expected {EXPECTED_PROBES} marker-carrying requests, one per "
        f"injection point except the one on {hosts[1]} the gate refuses",
        "zero would mean the crawl found no injection points (a response "
        "without 'html' in Content-Type does that) and every check below was "
        "skipped over an empty list",
    )
    # A6
    errors = report.get("errors") or []
    checks.expect(
        not errors, "no errors",
        *[f"[{e.get('scanner')}/{e.get('check')}] {e.get('message')}"
          for e in errors],
    )
    # A7: D14's threshold semantics.
    checks.expect(
        code == 1, f"exit 1 (got {code})",
        f"errors={len(errors)}, findings={len(findings)}",
    )

    # -- A8: the matched pairs, as one set comparison ------------------------ #
    got = {four_tuple(f) for f in active}
    detail = [f"unexpected: {t}" for t in sorted(got - EXPECTED)]
    detail += [f"missing:    {t}" for t in sorted(EXPECTED - got)]
    checks.expect(
        got == EXPECTED, f"exact finding set ({len(EXPECTED)})",
        *detail,
        "a missing tuple is a false negative; an extra one is a false positive "
        "and means a check fired where its guard should have held",
    )

    # -- the wire, read directly --------------------------------------------- #
    posts = [r for r in wire if r["method"] == "POST"]
    # A9
    checks.expect(
        len(posts) == EXPECTED_POSTS, f"POSTs arrived ({len(posts)})",
        f"expected {EXPECTED_POSTS} = 3 body points x (1 xss + 2 sqli); zero "
        "means the crawler never turned the form into an injection point, or "
        "the body never left the process (D51)",
    )
    # A10: D51's explicit content-type. Without it httpx builds a sync byte
    # stream that AsyncClient refuses, and the server answers 415.
    checks.expect(
        all(r["ctype"].startswith("application/x-www-form-urlencoded")
            for r in posts),
        "every POST declared urlencoded",
        *[f"ctype={r['ctype']!r}" for r in posts
          if not r["ctype"].startswith("application/x-www-form-urlencoded")],
    )
    # A11: sibling preservation -- the reason a body probe reaches the app.
    checks.expect(
        all("csrfmiddlewaretoken=rehearsal-token" in r["body"] for r in posts),
        "csrf preserved on every POST",
        *[f"body={r['body'][:160]!r}" for r in posts
          if "csrfmiddlewaretoken=rehearsal-token" not in r["body"]],
    )
    # A12: none of the 415/403/400 gates tripped, so every POST above was a
    # request the application actually accepted.
    checks.expect(
        all(r["status"] == 200 for r in posts),
        "the server accepted every POST with 200",
        *[f"{r['status']} {r['body'][:80]!r}" for r in posts
          if r["status"] != 200],
    )
    # A13: duplicate field names survive; dict(params) would collapse them and
    # the server's 400 gate would catch it.
    both = [r for r in posts if tags_of(r) == ["a", "b"]]
    twice = [r for r in posts if len(tags_of(r)) == 2]
    checks.expect(
        len(twice) == len(posts) and len(both) >= 1,
        f"a POST kept the repeated 'tags' field at both values ({len(both)})",
        *[f"tags={tags_of(r)!r}" for r in posts if len(tags_of(r)) != 2],
    )
    # A14: both open-redirect guards exercised, not merely reached.
    sentinel = [r for r in wire if REDIRECT_PROBE_PATH in decoded(r)]
    hit = {urlsplit(r["path"]).path for r in sentinel}
    checks.expect(
        len(sentinel) == len(REDIRECT_ROUTES) and hit == REDIRECT_ROUTES,
        f"sentinel sent to all three redirect routes (got {len(sentinel)})",
        f"reached {sorted(hit)}, expected {sorted(REDIRECT_ROUTES)}",
    )
    # A15: D8. Every payload observes; none exploits.
    offenders = [
        f"{r['method']} {decoded(r)[:100]!r} has {bad!r}"
        for r in wire for bad in FORBIDDEN if bad in decoded(r).lower()
    ]
    checks.expect(
        not offenders, f"detection-only across {len(wire)} requests",
        *offenders,
    )
    # A16
    expected_hosts = set(hosts)
    seen_hosts = {r["host"] for r in wire}
    checks.expect(
        seen_hosts <= expected_hosts,
        f"loopback only: {sorted(seen_hosts)}",
        f"expected a subset of {sorted(expected_hosts)}",
    )
    # A17
    agents = {r["ua"] for r in wire}
    checks.expect(
        len(agents) == 1 and UA_SHAPE.match(next(iter(agents)) or "") is not None,
        f"one honest UA: {sorted(agents)}",
        "expected exactly one agent of the shape "
        "'secscan/X.Y.Z (+https://...)'",
    )
    # A18: the positive control for A19. Without it, "no probe reached the
    # non-allowlisted host" would pass for a host nothing could reach.
    crossed = [r for r in wire if r["host"].startswith("127.0.0.2")]
    checks.expect(
        len(crossed) == 1,
        f"the crawl read the non-allowlisted spelling ({len(crossed)})",
        "the second listener is in scope.allowed_hosts, so exactly one crawl "
        "GET should arrive there",
    )
    # A19: the per-request active=True gate, observed from the CLI.
    leaked = [f"{r['method']} {r['path'][:100]}" for r in crossed
              if XSS_MARKER in decoded(r) or REDIRECT_PROBE_PATH in decoded(r)]
    checks.expect(
        not leaked,
        "no probe went to the in-scope, non-allowlisted host",
        *leaked,
    )
    # A19b: and the report says so. A18 and A19 together describe a host that was
    # crawled, turned into an injection point, and then never tested -- which for as
    # long as this gate has existed the report rendered as a host that was tested and
    # found clean, because `_send` swallowed the refusal and each check read the
    # missing response as a negative (D59). The skip is per host, not per check.
    gate_skips = [s for s in (scan.get("skipped") or []) if s.get("check") == "gate"]
    checks.expect(
        len(gate_skips) == 1 and "127.0.0.2" in (gate_skips[0].get("reason") or ""),
        "and the report discloses that it was refused, not cleared",
        f"skipped={scan.get('skipped')!r}",
    )
    # A20: the token bucket is real.
    span = wire[-1]["t"] - wire[0]["t"]
    floor = pacing_floor(len(wire), PHASE_A_RPS)
    checks.expect(
        span >= floor,
        f"paced: {len(wire)} requests over {span:.2f}s, floor {floor:.2f}s",
        f"at {PHASE_A_RPS} rps with a free burst of "
        f"{max(1.0, PHASE_A_RPS)} that span is too short to have been paced",
    )

    # -- D52, on a name the target chose ------------------------------------- #
    # A21: the request is not bounded, only the report is.
    verbatim = [r for r in wire if LONG_NAME in unquote(r["path"])]
    checks.expect(
        len(verbatim) >= 1,
        f"{len(LONG_NAME)}-char name went out verbatim ({len(verbatim)})",
        "the request is supposed to use point.param unmodified; only what is "
        "written into the report is bounded",
    )
    # A22: the count comes first. D56's version looped over this list and ran
    # zero assertions when it was empty, which printed as a pass.
    long_findings = [f for f in active
                     if ((f.get("location") or {}).get("param") or ""
                         ).startswith("nAAA")]
    if checks.expect(
        len(long_findings) == 1,
        f"exactly one /long finding ({len(long_findings)})",
        *[f"param={((f.get('location') or {}).get('param') or '')[:40]!r}"
          for f in long_findings],
    ):
        param = (long_findings[0].get("location") or {}).get("param") or ""
        evidence = long_findings[0].get("evidence") or ""
        # A23
        checks.expect(
            param == BOUNDED_LONG_NAME and len(param) == 120,
            f"bounded to 120 ({len(param)})",
            f"param ended {param[-20:]!r}",
        )
        # A24: the field cap did not eat the explanation.
        checks.expect(
            "reflected into the response unescaped" in evidence
            and evidence.endswith("are not being encoded."),
            "evidence sentence intact",
            f"evidence={evidence[:200]!r}",
        )
    else:
        # Keep the assertion count stable and the reason visible: A23 and A24
        # have nothing to read, and saying so is not the same as passing.
        checks.fail("bounded to 120 (no finding)",
                    "A22 failed, so there is no param to measure")
        checks.fail("evidence sentence intact (no finding)",
                    "A22 failed, so there is no evidence to read")

    # -- D44: what crosses from the target's data into the report ------------ #
    # A25. Paired with A8 and A26: this would pass trivially if /report never
    # fired, and those two require that it did.
    leaks = [c for c in CANARIES if c in out]
    checks.expect(not leaks, "no target bytes in the report", *leaks)
    # A26: the useful half survives redaction.
    sqli = [f for f in active
            if f.get("rule_id") == "dast.active.sqli-error"
            and urlsplit((f.get("location") or {}).get("url") or "").path
            == "/report"]
    checks.expect(
        len(sqli) == 1
        and "PostgreSQL database error" in (sqli[0].get("evidence") or ""),
        "the finding names the engine",
        *[f"evidence={(f.get('evidence') or '')[:160]!r}" for f in sqli],
    )
    # A27: scrub() on text the target chose, not on a fixture.
    checks.expect(
        COOKIE_NAME not in out, "token-shaped cookie name redacted",
        "the raw ghp_ token appears in the report",
    )
    # A28: redacted, not merely dropped. Without this A27 passes when no cookie
    # finding exists at all.
    cookie_params = [(f.get("location") or {}).get("param")
                     for f in findings
                     if (f.get("rule_id") or "").startswith("dast.cookies.")]
    checks.expect(
        COOKIE_REDACTED in cookie_params,
        "and the redacted form is in the report",
        f"dast.cookies params seen: {cookie_params!r}",
    )
    # A29: the DAST path as a whole. check_self_scan.py scans a code target, so
    # before this file nothing exercised the passive tier either.
    checks.expect(
        any(f.get("scanner") == "dast" for f in findings),
        "the passive tier also ran",
        "no passive finding against a site serving no security headers at all",
    )
    return len(probes)


# --------------------------------------------------------------------------- #
# phase B -- authorization withheld
# --------------------------------------------------------------------------- #

def phase_b(checks: Checks, url: str, config_path: Path) -> None:
    """The same scan with authorization withheld must send nothing.

    Without this half the file is passable by a build that ignores the gate
    entirely; without phase A it is passable by one that sends nothing at all.
    Neither direction alone says the gate carries information.
    """
    code, out, err, wire, _ = capture(url, config_path, authorized=False)
    print(f"  [{len(wire)} requests, exit {code}]")

    # B1: silence has to be refusal, not a failure to reach the host.
    checks.expect(
        bool(wire), "the refusal run still connected",
        f"zero requests arrived; exit was {code}",
    )
    # B2
    payloads = [
        f"{r['method']} {decoded(r)[:120]!r}"
        for r in wire
        if XSS_MARKER in decoded(r) or REDIRECT_PROBE_PATH in decoded(r)
    ]
    checks.expect(
        not payloads,
        f"no payload without --i-am-authorized ({len(wire)} reqs)",
        *payloads,
    )
    # B3: the user is told, rather than getting a quietly smaller scan.
    checks.expect(
        "authorization is not acknowledged" in (err or ""),
        "refusal announced on stderr",
        f"stderr={(err or '')[-300:]!r}",
    )
    # B4: disclosure both ways.
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        checks.fail("report claims no active traffic", out[-800:])
        return
    scan = report.get("scan") or {}
    checks.expect(
        scan.get("sent_active_traffic") is False
        and not (scan.get("active_scanners_run") or []),
        "report claims no active traffic",
        f"scan block was {scan!r}",
    )


# --------------------------------------------------------------------------- #
# phase C -- the request budget
# --------------------------------------------------------------------------- #

def phase_c(checks: Checks, url: str, config_path: Path,
            phase_a_probes: int) -> None:
    code, out, err, wire, _ = capture(url, config_path, authorized=True)
    markers = [r for r in wire if XSS_MARKER in decoded(r)]
    print(f"  [{len(wire)} requests, {len(markers)} markers, exit {code}]")

    # C1: measured against phase A rather than against a pinned number, because
    # which (point, check) pairs fit inside four requests depends on crawl
    # ordering. Both bounds matter: zero markers would also be "fewer".
    checks.expect(
        0 < len(markers) < phase_a_probes,
        f"budget cut probe traffic ({len(markers)} vs {phase_a_probes})",
        f"expected between 1 and {phase_a_probes - 1} markers under a "
        "4-request budget",
    )
    # C2: the skipped combinations are reported, not silently dropped -- exit 0
    # does not mean the surface was covered.
    checks.expect(
        "request budget" in (err or ""),
        "and said so on stderr",
        f"stderr={(err or '')[-300:]!r}",
    )


# --------------------------------------------------------------------------- #
# phase D -- a socket bound but never listened on
# --------------------------------------------------------------------------- #

def phase_d(checks: Checks, config_path: Path) -> None:
    """D56 said exit 3 was unreachable from a web target. It is one bind away."""
    dead = socket.socket()
    try:
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        code, out, err, wire, _ = capture(
            f"http://127.0.0.1:{dead_port}/", config_path, authorized=True,
        )
    finally:
        dead.close()

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        report = {}
    errors = report.get("errors") or []
    findings = report.get("findings") or []
    scan = report.get("scan") or {}
    print(f"  [exit {code}, errors {len(errors)}]")

    # D1: D54's exit code, and the correction to D56.
    checks.expect(code == 3, f"unreachable target exits 3 (got {code})",
                  f"errors={len(errors)}, findings={len(findings)}")
    # D2: the message text is platform/anyio wording and is deliberately not
    # asserted; the scanner/check pairs are ours. Both tiers must speak up. The
    # passive tier's failed GET was always recorded; the active tier's crawl failure
    # was not, and that silence is what made a host that never answered a single
    # packet produce an actively-scanned, clean-looking report (D59).
    checks.expect(
        sorted((e.get("scanner"), e.get("check")) for e in errors)
        == [("dast", "response"), ("dast-active", "crawl")],
        "and both tiers record what they could not reach",
        repr(errors)[:400],
    )
    # D3: 1 outranking 3 is only safe while this holds.
    checks.expect(not findings, "with no findings to mask them",
                  f"{len(findings)} findings on a host that never answered")
    # D4: the dead-port run is really dead -- nothing leaked onto either
    # listener, so D5 below is a statement about zero traffic.
    checks.expect(
        not wire, "and reached neither rehearsal site",
        *[f"{r['method']} {r['path'][:80]}" for r in wire[:5]],
    )
    # D5: what used to be D50's wart, now the assertion that closed it. This run
    # is the case that exposed it: the crawl never connects, so no injection point
    # exists, no check runs, and nothing attack-shaped is sent -- and the report
    # said "ACTIVE CHECKS RAN. This scan sent attack-shaped requests to the
    # target." because the claim was derived from which scanners were selected.
    # It is derived from the choke point's own counters now (D58), so this phase
    # is the one place where the report can be held to the same standard as the
    # server's log: both must say zero.
    checks.expect(
        scan.get("sent_active_traffic") is False
        and scan.get("active_requests_sent") == 0
        and "dast-active" not in (scan.get("active_scanners_run") or []),
        "and does not claim active traffic it never sent",
        f"scan block was {scan!r}",
    )


# --------------------------------------------------------------------------- #
# phase E -- in-process, the guard argv cannot reach
# --------------------------------------------------------------------------- #

def phase_e(checks: Checks, port: int) -> None:
    """``dast.active.enabled`` is defence in depth behind the CLI's own gate, so
    no command line can turn it off while still selecting the scanner. Only an
    in-process caller can, which is what D43's eight gate cases were about --
    and D43's first harness passed all eight with an empty registry, so the
    positive control runs first here."""
    sys.path.insert(0, str(ROOT / "src"))
    import scanner.scanners  # noqa: F401 - registration is a side effect
    from scanner.core.config import Config
    from scanner.core.egress import Egress
    from scanner.core.engine import Engine
    from scanner.core.gate import RequestGate
    from scanner.core.http import AsyncHttpClient
    from scanner.core.scope import Scope
    from scanner.core.target import Target

    def run(enabled: bool):
        WIRE.clear()
        config = Config.from_dict({
            "dast": {
                "enabled": False,  # only the active tier, so 5 requests not 55
                "active": {"enabled": enabled, "max_requests": 200},
            },
            "http": {"per_host_rps": 25.0, "timeout_s": 10.0},
        })
        scope = Scope(
            allowed_hosts={"127.0.0.1"},
            active_allowlist={"127.0.0.1"},
            authorized_ack=True,
        )
        target = Target(url=f"http://127.0.0.1:{port}/guard", scope=scope)

        async def go():
            gate = RequestGate(scope=scope, egress=Egress())
            async with AsyncHttpClient(
                gate, per_host_rps=25.0, timeout_s=10.0,
            ) as http:
                return await Engine().run(
                    target, active_enabled=True, http=http, config=config,
                )

        report = asyncio.run(go())
        wire = WIRE.snapshot()
        return report, wire, [r for r in wire if XSS_MARKER in decoded(r)]

    on_report, on_wire, on_probes = run(True)
    off_report, off_wire, off_probes = run(False)
    print(f"  [on: {len(on_wire)} reqs/{len(on_probes)} probes, "
          f"off: {len(off_wire)} reqs/{len(off_probes)} probes]")

    # E1: an API phase with only a negative case is exactly the shape that lies.
    checks.expect(
        "dast-active" in on_report.active_scanners_run
        and len(on_probes) == 1
        and len(on_report.findings) == 1,
        f"positive control: enabled=true probes and reports "
        f"({len(on_probes)} probes, {len(on_report.findings)} findings)",
        f"active_scanners_run={on_report.active_scanners_run!r}, "
        f"{len(on_wire)} requests, errors={len(on_report.errors)}",
    )
    # E2: the guard itself.
    checks.expect(
        not off_wire, "dast.active.enabled=false sent no probe",
        *[f"{r['method']} {r['path'][:80]}" for r in off_wire[:5]],
    )
    # E3: and says so. E2 is a statement about the wire; this is the same run read
    # from the artifact a person keeps, which for a scanner switched off in a config
    # file was previously indistinguishable from one that ran and found the target
    # clean -- `Ran: dast-active`, no findings, exit 0 (D58).
    off_skips = [(s.scanner, s.check) for s in off_report.skipped]
    checks.expect(
        ("dast-active", "") in off_skips
        and "dast-active" not in off_report.scanners_run
        and off_report.active_requests_sent == 0,
        "and the report discloses that it was switched off",
        f"skipped={off_skips!r}, scanners_run={off_report.scanners_run!r}",
    )
    # E4: the positive control again, from the same two fields, so E3 cannot be
    # passed by a report that always says "skipped". Both runs disable the passive
    # tier, so ("dast", "") is expected in both and is not what E3 is about.
    on_skips = [(s.scanner, s.check) for s in on_report.skipped]
    checks.expect(
        ("dast-active", "") not in on_skips
        and on_report.active_requests_sent == EXPECTED_GUARD_ACTIVE_REQUESTS,
        f"while the enabled run reports no skip and "
        f"{EXPECTED_GUARD_ACTIVE_REQUESTS} active requests",
        f"skipped={on_skips!r}, "
        f"active_requests_sent={on_report.active_requests_sent!r}",
    )


# --------------------------------------------------------------------------- #

def main() -> int:
    # ASCII only. A Windows console defaults to cp1252, where a box-drawing
    # character raises UnicodeEncodeError and the check then fails for a reason
    # that has nothing to do with what it checks.
    checks = Checks()
    started = time.monotonic()

    srv1, port1 = start_site("127.0.0.1")
    SITE["p1"] = port1
    try:
        srv2, port2 = start_site("127.0.0.2")
    except OSError as exc:
        # Never a silent skip: without the second listener the request-level
        # gate has no witness, and a gate with no witness is what this file
        # exists to prevent. macOS needs `sudo ifconfig lo0 alias 127.0.0.2 up`.
        srv1.shutdown()
        srv1.server_close()
        print("  FAIL the second loopback spelling (127.0.0.2) could not be "
              "bound")
        print(f"         {exc}")
        return 1
    SITE["p2"] = port2
    hosts = (f"127.0.0.1:{port1}", f"127.0.0.2:{port2}")

    tmp = tempfile.mkdtemp(prefix="secscan-rehearsal-")
    bailed = False
    try:
        main_config = Path(tmp) / "main.toml"
        main_config.write_text(MAIN_CONFIG, encoding="utf-8")
        capped_config = Path(tmp) / "capped.toml"
        capped_config.write_text(CAPPED_CONFIG, encoding="utf-8")
        url = f"http://127.0.0.1:{port1}/"

        print(f"  -- A: authorized, against {hosts[0]} "
              f"(+ {hosts[1]} in scope, not allowlisted) --")
        probes = phase_a(checks, url, main_config, hosts)
        if probes is None:
            bailed = True
        else:
            print("\n  -- B: the same scan with authorization withheld --")
            phase_b(checks, url, main_config)
            print("\n  -- C: the same site under a 4-request budget --")
            phase_c(checks, url, capped_config, probes)
            print("\n  -- D: a socket bound but never listened on --")
            phase_d(checks, main_config)
            print("\n  -- E: in-process, dast.active.enabled --")
            phase_e(checks, port1)
    finally:
        for srv in (srv1, srv2):
            srv.shutdown()
            srv.server_close()
        # ignore_errors because on Windows a handle held a moment longer turns
        # cleanup into a failure of a check that had already passed.
        shutil.rmtree(tmp, ignore_errors=True)

    wall = time.monotonic() - started
    if checks.failures:
        print(f"\n  FAILED: {len(checks.failures)} of {checks.total} "
              f"assertion(s) in {wall:.1f}s")
        for message in checks.failures:
            print(f"    - {message}")
        if bailed:
            print("    (bailed after the first assertion: nothing after it "
                  "could have carried information)")
        return 1
    print(f"\n  {checks.total} assertions, {wall:.1f}s: the active tier does "
          f"what it says, over a real socket.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
