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


def test_check_filter_limits_which_checks_run():
    http = _SiteHttp(reflect_xss=True)  # would trip XSS if that check ran
    findings = _collect(_ctx(http, overrides={"checks": ["sqli-error"]}))
    assert not any(f.rule_id == "dast.active.xss-reflected" for f in findings)


def test_request_budget_bounds_active_traffic():
    # Entry URL carries ten injectable params; without a budget that is dozens of
    # active requests. With max_requests=4 it must stop early.
    params = "&".join(f"p{i}=v{i}" for i in range(10))
    target = Target(url=f"https://example.com/search?{params}",
                    scope=Scope(allowed_hosts={"example.com"}))
    cfg = Config.from_dict({"dast": {"active": {"enabled": True, "max_requests": 4}}})
    http = _SiteHttp(reflect_xss=False)
    ctx = ScanContext(target=target, scope=target.scope, http=http, config=cfg)
    _collect(ctx)
    assert len(http.active_gets) <= 6  # 4 budget + at most one check's overshoot


def test_reaching_the_budget_is_disclosed_not_just_logged():
    """Stopping early is correct; stopping early quietly is the D58 failure again.
    The findings list of a run that tested a tenth of the surface is shaped exactly
    like the findings list of a run that tested all of it and liked what it saw."""
    params = "&".join(f"p{i}=v{i}" for i in range(10))
    target = Target(url=f"https://example.com/search?{params}",
                    scope=Scope(allowed_hosts={"example.com"}))
    cfg = Config.from_dict({"dast": {"active": {"enabled": True, "max_requests": 4}}})
    ctx = ScanContext(target=target, scope=target.scope, http=_SiteHttp(reflect_xss=False),
                      config=cfg)
    _collect(ctx)
    budget = [s for s in ctx.skipped if s.check == "budget"]
    assert len(budget) == 1
    assert "max_requests" in budget[0].reason
    assert not ctx.errors  # a bound that was honoured is not a failure


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
