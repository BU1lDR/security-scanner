import asyncio
from urllib.parse import parse_qsl, urlsplit

from scanner.core.config import Config
from scanner.core.context import ScanContext
from scanner.core.gate import OutOfScopeError
from scanner.core.scope import Scope
from scanner.core.target import Target
from scanner.scanners.dast_active.scanner import DastActiveScanner


class _Resp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/html"}


class _SiteHttp:
    """A tiny site: '/' links to '/search?q=hi'; '/search' reflects q unescaped."""

    def __init__(self, reflect_xss=True):
        self.reflect_xss = reflect_xss
        self.gets = []

    def _merged(self, url, params):
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query))
        if params:
            q.update(dict(params))
        return parts.path or "/", q

    async def get(self, url, *, active=False, params=None, **kwargs):
        self.gets.append({"url": url, "active": active})
        path, q = self._merged(url, params)
        if path == "/":
            return _Resp('<html><a href="/search?q=hi">search</a></html>')
        if path == "/search":
            val = q.get("q", "")
            body = f"you searched {val}" if self.reflect_xss else "static results"
            return _Resp(f"<html><body>{body}</body></html>")
        return _Resp("not found", status_code=404)

    async def post(self, url, *, active=False, data=None, **kwargs):
        self.gets.append({"url": url, "active": active})
        return _Resp("<html>posted</html>")

    @property
    def active_gets(self):
        return [g for g in self.gets if g["active"]]


def _ctx(http, overrides=None):
    target = Target(url="https://example.com/", scope=Scope(allowed_hosts={"example.com"}))
    base = {"dast": {"active": {"enabled": True}}}
    if overrides:
        base["dast"]["active"].update(overrides)
    cfg = Config.from_dict(base)
    return ScanContext(target=target, scope=target.scope, http=http, config=cfg)


def _collect(ctx):
    async def run():
        return [f async for f in DastActiveScanner().scan(ctx)]
    return asyncio.run(run())


def test_requires_url_and_active():
    assert DastActiveScanner.requires.url is True
    assert DastActiveScanner.requires.active is True
    assert DastActiveScanner.name == "dast-active"


def test_finds_reflected_xss_reached_through_the_crawl():
    http = _SiteHttp(reflect_xss=True)
    findings = _collect(_ctx(http))
    xss = [f for f in findings if f.rule_id == "dast.active.xss-reflected"]
    assert xss, "expected a reflected-XSS finding on the crawled /search?q= param"
    assert xss[0].location.param == "q"
    assert xss[0].scanner == "dast-active"
    # The crawl was passive; the checks went through the active gate.
    assert any(g["active"] for g in http.gets)
    assert any(not g["active"] for g in http.gets)


def test_disabled_active_flag_runs_nothing():
    http = _SiteHttp()
    ctx = _ctx(http)
    ctx.config = Config.from_dict({"dast": {"active": {"enabled": False}}})
    assert _collect(ctx) == []
    assert http.gets == []  # did not even crawl


class _SqlErrorSiteHttp(_SiteHttp):
    """The same little site, except ``/search`` answers a quoted ``q`` with a database
    error. It therefore trips *both* the XSS and the SQLi check, which is what makes a
    check filter testable in the positive direction."""

    _ERROR = "Warning: You have an error in your SQL syntax near ''' at line 1"

    async def get(self, url, *, active=False, params=None, **kwargs):
        self.gets.append({"url": url, "active": active})
        path, q = self._merged(url, params)
        if path == "/":
            return _Resp('<html><a href="/search?q=hi">search</a></html>')
        if path == "/search":
            val = q.get("q", "")
            if "'" in val:
                return _Resp(f"<html>{self._ERROR}</html>")
            return _Resp(f"<html><body>you searched {val}</body></html>")
        return _Resp("not found", status_code=404)


def test_the_unfiltered_default_runs_every_check():
    """The control for the test below. Without it, "only SQLi came back" is equally
    well explained by a site that only has SQL injection."""
    findings = _collect(_ctx(_SqlErrorSiteHttp()))
    assert {f.rule_id for f in findings} == {
        "dast.active.sqli-error", "dast.active.xss-reflected",
    }


def test_check_filter_limits_which_checks_run():
    """Both halves of it. This test asserted only that the unselected check did not
    fire, which is exactly what a filter selecting *nothing* also produces — the
    silent-narrowing failure that ``VALUE_CHOICES`` exists to close was invisible to
    the test that was supposed to be watching the filter."""
    findings = _collect(_ctx(_SqlErrorSiteHttp(), overrides={"checks": ["sqli-error"]}))
    assert {f.rule_id for f in findings} == {"dast.active.sqli-error"}


def test_a_check_name_that_matches_nothing_is_disclosed():
    """``Config.load`` rejects an unknown check name against a closed set, so a config
    file cannot reach the filter. ``Config.from_dict`` is lenient by design, and there
    the filter kept the intersection and said nothing: the tier ran zero checks, the
    engine reported dast-active as having run, and the empty findings list read as a
    clean bill of health for a site that trips two checks."""
    http = _SqlErrorSiteHttp()
    ctx = _ctx(http, overrides={"checks": ["sqli-erorr"]})
    assert _collect(ctx) == []
    dropped = [s for s in ctx.skipped if s.check == "checks"]
    assert len(dropped) == 1
    assert "sqli-erorr" in dropped[0].reason
    assert "no active check ran at all" in dropped[0].reason
    assert http.active_gets == []  # and nothing was tested, which is the point


def test_a_partly_unknown_check_list_still_runs_the_names_that_exist():
    """Dropping the typo and keeping the rest is the right behaviour; doing it quietly
    was not. The disclosure has to name what ran as well as what did not, because
    "one of your two checks was a typo" and "neither of your checks ran" are different
    reports."""
    ctx = _ctx(_SqlErrorSiteHttp(), overrides={"checks": ["sqli-error", "xss-reflcted"]})
    findings = _collect(ctx)
    assert {f.rule_id for f in findings} == {"dast.active.sqli-error"}
    dropped = [s for s in ctx.skipped if s.check == "checks"]
    assert len(dropped) == 1
    assert "xss-reflcted" in dropped[0].reason
    assert "only sqli-error ran" in dropped[0].reason


def _many_params_ctx(http, overrides=None):
    """A target whose entry URL carries ten injectable params, so the budget binds."""
    params = "&".join(f"p{i}=v{i}" for i in range(10))
    target = Target(url=f"https://example.com/search?{params}",
                    scope=Scope(allowed_hosts={"example.com"}))
    active = {"enabled": True, "max_requests": 4}
    active.update(overrides or {})
    cfg = Config.from_dict({"dast": {"active": active}})
    return ScanContext(target=target, scope=target.scope, http=http, config=cfg)


def test_request_budget_bounds_active_traffic():
    # Ten injectable params is dozens of active requests without a budget.
    http = _SiteHttp(reflect_xss=False)
    _collect(_many_params_ctx(http))
    assert len(http.active_gets) == 4


def test_the_request_budget_is_exact():
    """``max_requests`` was tested once per (point, check) pair rather than once per
    request, so ``sqli-error`` — which sends an untampered baseline and then the probe
    — was cleared against the limit and then walked past it. Five is the budget that
    catches it: the sixth request is the second half of a check the fifth started, and
    the old accounting let it go out."""
    http = _SiteHttp(reflect_xss=False)
    _collect(_many_params_ctx(http, {"max_requests": 5, "checks": ["sqli-error"]}))
    assert len(http.active_gets) == 5


def test_a_probe_the_gate_refused_does_not_spend_the_budget():
    """The tally was incremented before delegating, so a request the gate refused —
    one that never reached a socket — spent a budget whose entire purpose is to bound
    what the *target* receives. A host in scope to crawl but absent from
    ``active_allowlist`` could exhaust 200 requests having sent none, and the report
    then said the budget was reached beside an active-request count of zero. Worse in
    a mixed scan: the host nobody authorized eats the budget for the host that was."""
    ctx = _many_params_ctx(_RefusingHttp(reflect_xss=False))
    assert _collect(ctx) == []
    assert not [s for s in ctx.skipped if s.check == "budget"]
    gate = [s for s in ctx.skipped if s.check == "gate"]
    assert len(gate) == 1 and "example.com" in gate[0].reason


def test_reaching_the_budget_is_disclosed_not_just_logged():
    """Stopping early is correct; stopping early quietly is the D58 failure again.
    The findings list of a run that tested a tenth of the surface is shaped exactly
    like the findings list of a run that tested all of it and liked what it saw."""
    ctx = _many_params_ctx(_SiteHttp(reflect_xss=False))
    _collect(ctx)
    budget = [s for s in ctx.skipped if s.check == "budget"]
    assert len(budget) == 1
    assert "max_requests" in budget[0].reason
    assert not ctx.errors  # a bound that was honoured is not a failure


def test_a_check_that_needs_no_request_is_not_counted_as_a_budget_gap():
    """The count in that sentence has to mean something. Enforcing the budget inside
    the counter rather than in the loop means every check is still started, so
    ``open-redirect`` on a parameter that is not URL-shaped reaches its correct empty
    verdict after the budget is gone instead of being tallied as surface nobody
    looked at. Ten params, three checks: thirty combinations, of which the ten
    open-redirect ones never needed a request."""
    ctx = _many_params_ctx(_SiteHttp(reflect_xss=False))
    _collect(ctx)
    budget = [s for s in ctx.skipped if s.check == "budget"]
    assert len(budget) == 1
    assert " 17 " in f" {budget[0].reason} ", budget[0].reason


# ── what the scanner could not test ──────────────────────────────────────────


class _BrokenSiteHttp(_SiteHttp):
    """'/' links to '/broken', which the server cannot serve."""

    async def get(self, url, *, active=False, params=None, **kwargs):
        self.gets.append({"url": url, "active": active})
        path, _ = self._merged(url, params)
        if path == "/":
            return _Resp('<html><a href="/broken">b</a></html>')
        if path == "/broken":
            raise OSError("connection reset by peer")
        return _Resp("not found", status_code=404)


def test_pages_the_crawl_could_not_read_become_errors():
    """Coverage the scan did not get is recorded as an error, which is what moves the
    exit code off 0. An injection point that was never discovered cannot produce a
    finding, so without this the report reads as a clean scan of the whole site."""
    ctx = _ctx(_BrokenSiteHttp())
    assert _collect(ctx) == []
    crawl_errors = [e for e in ctx.errors if e.check == "crawl"]
    assert len(crawl_errors) == 1
    assert "fetch-failed" in crawl_errors[0].message
    assert "/broken" in crawl_errors[0].message
    assert "OSError" in crawl_errors[0].message


class _DeadLinkSiteHttp(_SiteHttp):
    async def get(self, url, *, active=False, params=None, **kwargs):
        self.gets.append({"url": url, "active": active})
        path, _ = self._merged(url, params)
        if path == "/":
            return _Resp('<html><a href="/gone">g</a></html>')
        return _Resp("not found", status_code=404)


def test_a_dead_link_is_not_an_error():
    """The other side of the policy. 404s are ordinary on real sites; an exit code
    that fires on every one of them stops carrying information."""
    ctx = _ctx(_DeadLinkSiteHttp())
    _collect(ctx)
    assert ctx.errors == []


class _RefusingHttp(_SiteHttp):
    """Serves the crawl, refuses every active request — the shape of a host that is
    in scope to look at but not in ``scope.active_allowlist``."""

    async def get(self, url, *, active=False, params=None, **kwargs):
        if active:
            self.gets.append({"url": url, "active": True})
            raise OutOfScopeError(f"Active check not authorized for {url!r}")
        return await super().get(url, active=active, params=params, **kwargs)


def test_a_gate_refusal_is_a_skip_not_a_clean_negative():
    """``_send`` used to catch every exception and return ``None``, and every check
    reads a missing response as "no marker came back, nothing wrong here". So a host
    the operator had deliberately kept out of the active allowlist was reported as a
    host that had been actively tested and found sound — the most load-bearing
    version of D42's conflation, because the reader's next action is to ship."""
    ctx = _ctx(_RefusingHttp(reflect_xss=True))
    assert _collect(ctx) == []
    gate = [s for s in ctx.skipped if s.check == "gate"]
    assert len(gate) == 1                      # one per host, not one per check
    assert "example.com" in gate[0].reason
    assert "refused" in gate[0].reason
    # A refusal is a configuration, not a crash: it must not read as a broken scan.
    assert ctx.errors == []


class _BaselinelessHttp(_SiteHttp):
    """Serves the crawl. On the probes it answers the quoted value with a database
    error and never answers the untampered one."""

    _ERROR = "Warning: You have an error in your SQL syntax near ''' at line 1"

    async def get(self, url, *, active=False, params=None, **kwargs):
        if not active:
            return await super().get(url, active=active, params=params, **kwargs)
        self.gets.append({"url": url, "active": True})
        val = dict(params or []).get("q", "")
        if "'" not in val:
            raise TimeoutError("read timed out")
        return _Resp(f"<html>{self._ERROR}</html>")


def test_a_sqli_finding_is_never_built_on_a_comparison_that_did_not_happen():
    """``sqli-error``'s whole claim is comparative — this database error appeared and
    the untampered request did not produce it. With ``_send`` swallowing failures, a
    baseline that timed out arrived as ``None``, read as an empty page, and satisfied
    "no error in the baseline"; the check then reported HIGH SQL injection against a
    request that was never answered. That is the over-claiming direction of the same
    defect, and it lands in the report as a finding somebody will go and fix."""
    ctx = _ctx(_BaselinelessHttp(), overrides={"checks": ["sqli-error"]})
    findings = _collect(ctx)
    assert not [f for f in findings if f.rule_id == "dast.active.sqli-error"]
    assert ctx.errors, "a parameter it could not decide about must be recorded as such"
    assert any("timed out" in e.message for e in ctx.errors)


class _TimingOutHttp(_SiteHttp):
    """Serves the crawl, then times out on the probes."""

    async def get(self, url, *, active=False, params=None, **kwargs):
        if active:
            self.gets.append({"url": url, "active": True})
            raise TimeoutError("read timed out")
        return await super().get(url, active=active, params=params, **kwargs)


def test_a_probe_that_never_got_an_answer_is_an_error_not_a_negative():
    """The distinction the refusal test depends on: a refusal is deliberate and a
    timeout is not, and the old blanket ``except Exception`` in ``_send`` erased
    both into the same clean report."""
    ctx = _ctx(_TimingOutHttp(reflect_xss=True))
    assert _collect(ctx) == []
    assert ctx.errors, "a probe that timed out must not read as a tested parameter"
    assert all(e.scanner == "dast-active" for e in ctx.errors)
    assert any("timed out" in e.message for e in ctx.errors)
    assert not [s for s in ctx.skipped if s.check == "gate"]
