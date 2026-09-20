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
one with the flaw's guard in place -- and the assertion is an *exact* match on
which rules fired per route. A target containing only flaws proves the checks
fire, not that they are right, and this file's per-route equality is what catches
a check that has started firing on everything:

===================  =====================================  ========================
route                planted                                must report
===================  =====================================  ========================
``/reflect``         reflects ``q`` unescaped               ``xss-reflected``
``/reflect-safe``    the same, HTML-escaped                 nothing
``/report``          DB error only when ``'`` is present    ``sqli-error``
``/report-broken``   DB error regardless of input           nothing (unattributable)
``/go``              honours ``next`` as a redirect         ``open-redirect``
``/go-fixed``        302s to a fixed internal path          nothing
``/long``            reflects a 4000-char *parameter name*  ``xss-reflected`` (D52)
``/comment``         reflects a POST body field             ``xss-reflected`` (D51)
===================  =====================================  ========================

**Read the wire, not the exit code.** Every trap that makes this kind of
rehearsal vacuous ends in a clean-looking exit 0: the crawler needs the literal
substring ``html`` in ``Content-Type`` and Python's ``BaseHTTPRequestHandler``
does not send one for you; ``crawler._get`` swallows every exception and returns
``None``, so connection-refused and a timed-out fetch leave no record; a redirect
on the entry path empties the crawl. Asserting ``exit == 1`` would pass while the
scanner never reached the site. So the server keeps its own log of every request
it receives -- full method, full untruncated path, full body -- and the
assertions are made against that. It is an independent witness: the scanner runs
as a subprocess, so nothing it believes about itself can reach this log.

**Both directions, as elsewhere in tools/.** The second half re-runs the same
scan with ``--i-am-authorized`` withheld and requires that *zero* probe payloads
reach the socket. One half alone is passable by a broken build: a scanner that
sends nothing passes the refusal half, and one that ignores the gate entirely
passes the first.

**The positive control runs first**, because D43's first harness reported PASS on
every case while the scanner registry was empty and nothing had run. An empty
result read as a good result. Here, before any judgement about findings, the
assertions require that requests actually arrived, that the active scanner was
actually selected, and that probe payloads are actually present on the wire.

Usage::

    python tools/check_active_rehearsal.py

Loopback only, and no non-loopback network. The open-redirect probe names
``example.org`` in a *parameter value*; the request itself goes to ``127.0.0.1``,
and ``core/http.py`` builds its client with ``follow_redirects=False``, so the
302 this site returns is read and never followed. The assertions check that the
only host contacted was the loopback one.
"""

from __future__ import annotations

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
# change to either has to be made deliberately in two places.
XSS_MARKER = "sxqz91kv7"
XSS_SIGNATURE = f"<{XSS_MARKER}>"
REDIRECT_PROBE_PATH = "secscan-open-redirect-probe"
REDIRECT_SENTINEL_HOST = "example.org"

# A parameter name chosen by the *target*, long enough to exercise D52's bounding
# on data that arrived over the network rather than from a fixture. Deliberately
# free of any substring in the open-redirect hint list, so only the XSS check
# fires on this route and the attribution stays unambiguous.
LONG_NAME = "n" + "A" * 3999

# Matches checks.py's MySQL group ("You have an error in your SQL syntax").
MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near ''' at line 1"
)

# Exploitation shapes the payloads must never contain (D8: detection-only). The
# XSS marker is an inert unknown tag and the SQLi probe is one quote; anything
# below would mean the tier had started trying to *use* a flaw instead of observe
# it. Checked against the percent-decoded path and body of every request.
FORBIDDEN = (
    "or 1=1", "union", "sleep(", "waitfor", "benchmark(", "drop table",
    "xp_cmdshell", "<script", "onerror=", "onload=", "javascript:",
)

INDEX = f"""<!doctype html>
<html><body><h1>rehearsal target</h1>
<a href="/reflect?q=hello">reflect</a>
<a href="/reflect-safe?q=hello">reflect-safe</a>
<a href="/report?name=alice">report</a>
<a href="/report-broken?name=alice">report-broken</a>
<a href="/go?next=/home">go</a>
<a href="/go-fixed?next=/home">go-fixed</a>
<a href="/long?{LONG_NAME}=x">long</a>
<a href="/form">form</a>
</body></html>"""

# A hidden CSRF field beside the targeted one, so the run shows sibling fields
# surviving at their captured values -- the property that makes a body probe
# reach the application at all rather than bouncing off its CSRF check.
FORM_PAGE = """<!doctype html>
<html><body>
<form method="POST" action="/comment">
<input type="hidden" name="csrfmiddlewaretoken" value="rehearsal-token">
<input type="text" name="comment" value="hi">
<input type="submit" name="post" value="Post">
</form>
</body></html>"""


# --------------------------------------------------------------------------- #
# the site
# --------------------------------------------------------------------------- #

class Wire:
    """The server's own record of what it was sent. The independent witness."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: list[dict] = []

    def record(self, method: str, path: str, body: str) -> None:
        with self._lock:
            # Untruncated, deliberately. A log that shortens what it stores
            # cannot answer the question this gate exists to answer -- and a
            # 4000-character parameter name is exactly what a truncating log
            # hides. BaseHTTPRequestHandler.log_message truncates; it is
            # silenced below in favour of this.
            self.requests.append({"method": method, "path": path, "body": body})

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
    server_version = "rehearsal/1.0"

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        pass  # superseded by Wire.record, which does not truncate

    # -- plumbing ----------------------------------------------------------- #
    def _send(self, status: int, body: bytes = b"",
              ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        # Always present, always containing "html" for HTML: crawler._is_html
        # looks for that literal substring and skips link and form extraction
        # without it, which yields zero injection points and a healthy-looking
        # empty result.
        self.send_header("Content-Type", ctype)
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
        WIRE.record("GET", self.path, "")
        parts = urlsplit(self.path)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        path = parts.path

        if path == "/":
            return self._send(200, INDEX.encode())
        if path == "/form":
            return self._send(200, FORM_PAGE.encode())
        if path == "/home":
            return self._send(200, self._page("<p>home</p>"))

        # XSS pair -----------------------------------------------------------
        if path == "/reflect":
            return self._send(200, self._page(
                f"<p>results for {query.get('q', '')}</p>"))
        if path == "/reflect-safe":
            return self._send(200, self._page(
                f"<p>results for {html.escape(query.get('q', ''))}</p>"))

        # SQLi pair. Neither route reflects its input: the XSS check runs here
        # too, and a reflection would raise a second finding on these routes and
        # blur which check the pair is actually testing.
        if path == "/report":
            if "'" in query.get("name", ""):
                return self._send(200, self._page(f"<p>{MYSQL_ERROR}</p>"))
            return self._send(200, self._page("<p>no such user</p>"))
        if path == "/report-broken":
            # Errors whatever it is sent, so the baseline request already carries
            # the signature and checks.py refuses to attribute it to the input.
            return self._send(200, self._page(f"<p>{MYSQL_ERROR}</p>"))

        # open-redirect pair -------------------------------------------------
        if path == "/go":
            nxt = query.get("next", "")
            if nxt.startswith(("http://", "https://")):
                return self._send(302, b"", extra={"Location": nxt})
            return self._send(200, self._page("<p>home</p>"))
        if path == "/go-fixed":
            # A real 3xx that ignores the parameter. Exercises the check's
            # hostname test rather than its status test: the status passes and
            # the Location host is not the sentinel, so there is no finding.
            return self._send(302, b"", extra={"Location": "/home"})

        # D52: a 4000-character parameter name, chosen by the target ----------
        if path == "/long":
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                if len(name) > 100:
                    return self._send(200, self._page(f"<p>echo {value}</p>"))
            return self._send(200, self._page("<p>nothing</p>"))

        return self._send(404, self._page("<p>not found</p>"))

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        WIRE.record("POST", self.path, raw)
        fields = dict(parse_qsl(raw, keep_blank_values=True))
        if urlsplit(self.path).path == "/comment":
            return self._send(200, self._page(
                f"<p>said {fields.get('comment', '')}</p>"))
        return self._send(404, self._page("<p>not found</p>"))


def start_site() -> tuple[ThreadingHTTPServer, int]:
    """Bind 127.0.0.1 on an ephemeral port, and do not return until it accepts.

    Port 0 rather than a fixed number so concurrent CI jobs on one runner cannot
    collide. The accept-poll closes the race the traps section names: if secscan
    starts first, every fetch is refused, crawler._get returns None for each, and
    the scan reports a clean site it never reached.
    """
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True  # so shutdown cannot hang CI on a live connection
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    for _ in range(100):
        with socket.socket() as probe:
            probe.settimeout(0.25)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return srv, port
    raise RuntimeError(f"the rehearsal site never accepted on port {port}")


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


CONFIG = f"""
# include_post has no CLI flag, so without this file the body path -- the exact
# code path whose silently-empty POST shipped (D51) -- is unreachable from argv
# and the rehearsal would quietly test only query parameters.
[dast.active]
include_post = true
max_requests = 200

[dast.crawler]
max_depth = 2
max_pages = 50

[http]
# The rate limiter is paced for somebody else's server. Over loopback it only
# buys wall-clock in CI, and how it paces is a unit-testable property rather
# than something this gate is positioned to observe.
per_host_rps = 25.0
timeout_s = 10.0
"""


def run_scan(port: int, config_path: Path, *, authorized: bool
             ) -> tuple[int, str, str]:
    args = [
        f"http://127.0.0.1:{port}/", "--active",
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

    def ok(self, message: str) -> None:
        print(f"  ok   {message}")

    def fail(self, message: str, *detail: str) -> None:
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


#: route -> the exact set of active rule_ids that must be reported against it.
EXPECTED: dict[str, set[str]] = {
    "/reflect": {"dast.active.xss-reflected"},
    "/reflect-safe": set(),
    "/report": {"dast.active.sqli-error"},
    "/report-broken": set(),
    "/go": {"dast.active.open-redirect"},
    "/go-fixed": set(),
    "/long": {"dast.active.xss-reflected"},
    "/comment": {"dast.active.xss-reflected"},
}


def decoded(request: dict) -> str:
    return unquote(request["path"]) + " " + unquote(request["body"])


def authorized_half(port: int, config_path: Path, checks: Checks) -> None:
    WIRE.clear()
    code, out, err = run_scan(port, config_path, authorized=True)
    wire = WIRE.snapshot()

    # -- positive control, before any judgement about findings --------------- #
    # D43's harness reported PASS on every gate case while the registry was
    # empty and nothing had run at all. These four say the machinery moved.
    if not checks.expect(
        bool(wire), "the site received requests",
        f"zero requests arrived; exit was {code}",
        "the scanner never reached the site, so nothing below means anything",
        (err or "")[-500:],
    ):
        return

    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        checks.fail("the JSON report parses", out[-1500:], (err or "")[-500:])
        return

    scan = report.get("scan") or {}
    findings = report.get("findings") or []
    checks.expect(
        "dast-active" in (scan.get("active_scanners_run") or []),
        "the active scanner was selected and recorded (D49)",
        f"scan block was {scan!r}",
    )
    checks.expect(
        scan.get("sent_active_traffic") is True,
        "the report discloses that active traffic was sent",
        f"sent_active_traffic was {scan.get('sent_active_traffic')!r}",
    )
    probes = [r for r in wire if XSS_MARKER in decoded(r)]
    checks.expect(
        bool(probes), f"probe payloads reached the socket ({len(probes)} of "
        f"{len(wire)} requests carried the marker)",
        "requests arrived but none were active probes: the crawl found no "
        "injection points, so every check below was skipped",
    )

    # -- the scan ran to completion ------------------------------------------ #
    # Per D54 a recorded ScanError exits 3. Nothing here should error, and if
    # something does, the findings are an incomplete answer rather than a clean
    # one -- which is the whole point of that exit code.
    errors = report.get("errors") or []
    checks.expect(
        not errors, "no check recorded an error",
        *[f"[{e.get('scanner')}/{e.get('check')}] {e.get('message')}"
          for e in errors],
    )
    checks.expect(
        code == 1, "exit 1: a finding at or above the threshold (D14)",
        f"exit was {code}; errors={len(errors)}, findings={len(findings)}",
    )

    # -- matched pairs: exact per-route equality ----------------------------- #
    active = [f for f in findings if f.get("scanner") == "dast-active"]
    by_route: dict[str, set[str]] = {path: set() for path in EXPECTED}
    stray: list[str] = []
    for finding in active:
        url = (finding.get("location") or {}).get("url") or ""
        path = urlsplit(url).path
        if path in by_route:
            by_route[path].add(finding.get("rule_id") or "?")
        else:
            stray.append(f"{finding.get('rule_id')} at {url}")

    for path, expected in EXPECTED.items():
        got = by_route[path]
        if got == expected:
            checks.ok(
                f"{path}: {', '.join(sorted(expected)) if expected else 'nothing'}"
                f" -- {'detected' if expected else 'correctly quiet'}"
            )
            continue
        checks.fail(
            f"{path}: expected {sorted(expected) or 'nothing'}, got {sorted(got)}",
            "a missing rule is a false negative; an extra one is a false "
            "positive and means the check fired where its guard should have held",
        )
    checks.expect(
        not stray, "no active finding landed on an unexpected route", *stray,
    )

    # -- the wire, read directly --------------------------------------------- #
    posts = [r for r in wire if r["method"] == "POST"]
    checks.expect(
        bool(posts), "the body path ran: at least one POST reached the server",
        "include_post was set, so zero POSTs means the crawler never turned the "
        "form into an injection point, or the body never left the process (D51)",
    )
    probed = [r for r in posts if XSS_MARKER in r["body"]]
    checks.expect(
        bool(probed), "a POST body carried the probe, urlencoded",
        *[f"POST {r['path']} body={r['body'][:160]!r}" for r in posts],
    )
    checks.expect(
        all("csrfmiddlewaretoken=rehearsal-token" in r["body"] for r in posts),
        "every POST kept the CSRF field at its captured value",
        *[f"body={r['body'][:160]!r}" for r in posts
          if "csrfmiddlewaretoken=rehearsal-token" not in r["body"]],
    )

    sentinel = [r for r in wire if REDIRECT_PROBE_PATH in decoded(r)]
    checks.expect(
        bool(sentinel),
        f"the open-redirect sentinel was sent to loopback, not to "
        f"{REDIRECT_SENTINEL_HOST}",
        "the probe never went out, so the open-redirect finding above cannot "
        "have come from a real 3xx",
    )

    offenders = [
        f"{r['method']} {decoded(r)[:120]!r} contains {bad!r}"
        for r in wire for bad in FORBIDDEN if bad in decoded(r).lower()
    ]
    checks.expect(
        not offenders,
        f"every payload was detection-only across all {len(wire)} requests (D8)",
        *offenders,
    )

    # -- D52, on data the target chose -------------------------------------- #
    verbatim = [r for r in wire if LONG_NAME in unquote(r["path"])]
    checks.expect(
        bool(verbatim),
        f"the {len(LONG_NAME)}-character parameter name went out verbatim",
        "the request is supposed to use point.param unmodified; only what is "
        "written into the report is bounded",
    )
    long_findings = [
        f for f in active
        if (f.get("location") or {}).get("url", "").endswith("/long")
    ]
    for finding in long_findings:
        param = (finding.get("location") or {}).get("param") or ""
        evidence = finding.get("evidence") or ""
        checks.expect(
            len(param) < len(LONG_NAME) and param.endswith("(truncated)"),
            f"the report bounded that name to {len(param)} characters (D52)",
            f"param was {len(param)} characters, ending {param[-20:]!r}",
        )
        checks.expect(
            "reflected into the response" in evidence,
            "the evidence still explains what was wrong (D52)",
            "the bounded name consumed the field budget and truncated away the "
            "clause that said what the finding means",
            f"evidence={evidence[:200]!r}",
        )

    # The passive path is gated by this run too: check_self_scan.py scans a code
    # target, so before this file nothing exercised dast either.
    checks.expect(
        any(f.get("scanner") == "dast" for f in findings),
        "the passive DAST path also ran end-to-end",
        "no passive finding against a site serving no security headers at all",
    )


def refusal_half(port: int, config_path: Path, checks: Checks) -> None:
    """The same scan with authorization withheld must send nothing.

    Without this half the file is passable by a build that ignores the gate
    entirely; without the half above it is passable by one that sends nothing at
    all. Neither direction alone says the gate carries information.
    """
    WIRE.clear()
    code, out, err = run_scan(port, config_path, authorized=False)
    wire = WIRE.snapshot()

    checks.expect(
        bool(wire),
        "the passive-only run still reached the site (so its silence is "
        "refusal, not a failure to connect)",
        f"zero requests arrived; exit was {code}",
    )
    payloads = [
        f"{r['method']} {decoded(r)[:120]!r}"
        for r in wire
        if XSS_MARKER in decoded(r) or REDIRECT_PROBE_PATH in decoded(r)
    ]
    if payloads:
        # Spelled out rather than run through expect(), because the passing
        # message ("not one payload, all passive") is a claim that would be false
        # on the failing branch, and a gate that misdescribes its own failure
        # sends the reader looking in the wrong place.
        checks.fail(
            f"{len(payloads)} probe payload(s) went out with no authorization: "
            f"the fail-closed gate did not hold",
            *payloads,
        )
    else:
        checks.ok(
            f"not one probe payload was sent without --i-am-authorized "
            f"({len(wire)} requests, all passive)"
        )
    checks.expect(
        "authorization is not acknowledged" in (err or ""),
        "the refusal was announced on stderr rather than being silent",
        f"stderr={(err or '')[-300:]!r}",
    )
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        checks.fail("the JSON report parses for the refusal case", out[-800:])
        return
    scan = report.get("scan") or {}
    checks.expect(
        scan.get("sent_active_traffic") is False
        and not (scan.get("active_scanners_run") or []),
        "the report does not claim active traffic it never sent (D49)",
        f"scan block was {scan!r}",
    )
    checks.expect(
        not [f for f in (report.get("findings") or [])
             if f.get("scanner") == "dast-active"],
        "no active finding was reported",
    )


# --------------------------------------------------------------------------- #

def main() -> int:
    # ASCII only. A Windows console defaults to cp1252, where a box-drawing
    # character raises UnicodeEncodeError and the check then fails for a reason
    # that has nothing to do with what it checks.
    checks = Checks()
    srv, port = start_site()
    tmp = tempfile.mkdtemp(prefix="secscan-rehearsal-")
    try:
        config_path = Path(tmp) / "rehearsal.toml"
        config_path.write_text(CONFIG, encoding="utf-8")
        print(f"  -- authorized, against 127.0.0.1:{port} --")
        authorized_half(port, config_path, checks)
        print("\n  -- the same scan with authorization withheld --")
        refusal_half(port, config_path, checks)
    finally:
        srv.shutdown()
        srv.server_close()
        # ignore_errors because on Windows a handle held a moment longer turns
        # cleanup into a failure of a check that had already passed.
        shutil.rmtree(tmp, ignore_errors=True)

    if checks.failures:
        print(f"\n  FAILED: {len(checks.failures)} assertion(s)")
        for message in checks.failures:
            print(f"    - {message}")
        return 1
    print("\n  the active tier does what it says, over a real socket.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
