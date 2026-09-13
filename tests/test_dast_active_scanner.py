import asyncio
from urllib.parse import parse_qsl, urlsplit

from scanner.core.config import Config
from scanner.core.context import ScanContext
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
