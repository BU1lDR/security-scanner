import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanner.core.config import Config
from scanner.core.context import ScanContext
from scanner.core.egress import Egress
from scanner.core.gate import RequestGate
from scanner.core.scope import Scope
from scanner.core.target import Target
from scanner.scanners.dast import scanner as dast_scanner
from scanner.scanners.dast.scanner import DastScanner

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _expired_cert():
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now - timedelta(days=10))
        .sign(_KEY, hashes.SHA256())
    )


class _Headers:
    def __init__(self, mapping, set_cookie):
        self._m = mapping
        self._sc = set_cookie

    def items(self):
        return self._m.items()

    def get_list(self, name):
        if name.lower() == "set-cookie":
            return list(self._sc)
        v = self._m.get(name)
        return [v] if v is not None else []


class _Resp:
    def __init__(self, status_code=200, text="", headers=None, set_cookie=None):
        self.status_code = status_code
        self.text = text
        self.headers = _Headers(headers or {}, set_cookie or [])


def _redirect(location, status=302):
    """A 3xx, spelled the way a server spells one: empty body, Location header.

    The header key is lowercase because ``_Headers`` has no ``get`` and matches
    exactly through ``get_list`` — which is the fallback path the redirect helper
    in the source has to cope with, so exercising it here is deliberate.
    """
    return _Resp(status_code=status, text="", headers={"location": location})


class _FakeHttp:
    def __init__(self, entry_url, entry_resp, by_path=None, raise_entry=False,
                 by_url=None):
        self.entry_url = entry_url
        self.entry_resp = entry_resp
        self.by_path = by_path or {}
        self.by_url = by_url or {}
        self.raise_entry = raise_entry
        self.gets: list[str] = []
        # The real client carries the gate the TLS probe has to authorize through,
        # so a double that omits it would hide the wiring this fake is here to test.
        self.gate = RequestGate(Scope.from_url(entry_url), Egress())

    async def get(self, url, **kwargs):
        self.gets.append(url)
        if url in self.by_url:                    # exact match wins: a redirect
            return self.by_url[url]               # target differs by more than path
        if url == self.entry_url:
            if self.raise_entry:
                raise RuntimeError("connection refused")
            return self.entry_resp
        for path, resp in self.by_path.items():
            if url.endswith(path):
                return resp
        return _Resp(404, "not found")


def _ctx(url, http, *, tls=False, subdomains=False):
    target = Target(url=url)
    cfg = Config.from_dict({"dast": {"tls": {"enabled": tls}}})
    scope = target.scope
    if subdomains:
        scope = Scope(allowed_hosts=set(scope.allowed_hosts), allow_subdomains=True)
    return ScanContext(target=target, scope=scope, http=http, config=cfg)


def _collect(ctx):
    async def run():
        return [f async for f in DastScanner().scan(ctx)]
    return asyncio.run(run())


def test_requires_a_url_not_code():
    assert DastScanner.requires.url is True
    assert DastScanner.requires.active is False
    assert DastScanner.applicable(Target(url="https://example.com/")) is True
    assert DastScanner.applicable(Target(code_path=".")) is False


def test_missing_headers_from_entry_response_are_reported():
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(200, "<html></html>", headers={}))
    ids = {f.rule_id for f in _collect(_ctx(url, http))}
    assert "dast.headers.missing-csp" in ids
    assert "dast.headers.missing-hsts" in ids


def test_insecure_cookie_from_entry_response_is_reported():
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(200, headers={}, set_cookie=["sid=abc; Path=/"]))
    ids = {f.rule_id for f in _collect(_ctx(url, http))}
    assert "dast.cookies.missing-secure" in ids


def test_exposed_env_file_is_reported_by_the_scanner():
    url = "https://example.com/"
    entry = _Resp(200, headers={"Content-Security-Policy": "default-src 'self'"})
    http = _FakeHttp(url, entry, by_path={".env": _Resp(200, "API_KEY=abc\n")})
    ids = {f.rule_id for f in _collect(_ctx(url, http))}
    assert "dast.exposed.env-file" in ids


def test_entry_fetch_failure_is_isolated_not_fatal():
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(), raise_entry=True)
    ctx = _ctx(url, http)
    findings = _collect(ctx)  # must not raise
    assert any(e.scanner == "dast" for e in ctx.errors)


def test_tls_findings_flow_through_when_enabled(monkeypatch):
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(200, headers={}))

    async def fake_fetch(u, gate, **kwargs):
        return _expired_cert(), "TLSv1.3"

    monkeypatch.setattr(dast_scanner, "fetch_tls", fake_fetch)
    ids = {f.rule_id for f in _collect(_ctx(url, http, tls=True))}
    assert "dast.tls.expired-cert" in ids


def test_the_tls_probe_is_handed_the_http_clients_own_gate(monkeypatch):
    """The wiring core/http.py already claimed existed.

    A probe holding some *other* gate would enforce some other scope, which
    defeats the point of there being a single boundary — so this asserts object
    identity with the client's gate, not merely that a gate was passed.
    """
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(200, headers={}))
    seen = {}

    async def fake_fetch(u, gate, **kwargs):
        seen.update(url=u, gate=gate)
        return _expired_cert(), "TLSv1.3"

    monkeypatch.setattr(dast_scanner, "fetch_tls", fake_fetch)
    ctx = _ctx(url, http, tls=True)
    _collect(ctx)
    assert seen["url"] == url
    assert seen["gate"] is http.gate
    assert ctx.errors == []


def test_disabled_scanner_yields_nothing():
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(200, headers={}))
    target = Target(url=url)
    cfg = Config.from_dict({"dast": {"enabled": False}})
    ctx = ScanContext(target=target, scope=target.scope, http=http, config=cfg)
    assert _collect_ctx(ctx) == []


def _collect_ctx(ctx):
    async def run():
        return [f async for f in DastScanner().scan(ctx)]
    return asyncio.run(run())


# ---------------------------------------------------------------------------
# Redirects (D62). Every check in this tier used to be pointed at the entry
# URL's own response. When that response was a 302 the tier graded the stub and
# called it the site.


def test_headers_are_graded_on_the_landing_response_not_the_redirect():
    """The stub has no Content-Security-Policy because it has no document to
    protect, and no X-Frame-Options because it has nothing framable. Grading it
    produced five findings about a response that was never the page -- false
    positives and total blindness to the real headers, in one scan."""
    url = "https://example.com/"
    landing = "https://example.com/home"
    secure = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    http = _FakeHttp(url, _redirect("/home"),
                     by_url={landing: _Resp(200, "<html></html>", headers=secure)})
    ctx = _ctx(url, http)
    findings = _collect(ctx)
    assert landing in http.gets
    assert [f.rule_id for f in findings if f.rule_id.startswith("dast.headers")] == []
    assert ctx.errors == []


def test_a_missing_header_on_the_landing_page_is_still_found_and_located_there():
    """The other direction: the test above is passed by a tier that grades nothing
    at all."""
    url = "https://example.com/"
    landing = "https://example.com/home"
    http = _FakeHttp(url, _redirect("/home"),
                     by_url={landing: _Resp(200, "<html></html>", headers={})})
    findings = [f for f in _collect(_ctx(url, http))
                if f.rule_id == "dast.headers.missing-csp"]
    assert len(findings) == 1
    assert findings[0].location.url == landing


def test_a_cookie_set_on_a_redirect_hop_is_still_checked():
    """A Set-Cookie on a 302 is the ordinary shape of a login, and a session
    cookie without Secure is no less exposed for having arrived on a response
    with no body. Cookies are the one signal read from every hop."""
    url = "https://example.com/"
    landing = "https://example.com/home"
    hop = _Resp(302, "", headers={"location": "/home"}, set_cookie=["sid=abc; Path=/"])
    http = _FakeHttp(url, hop, by_url={landing: _Resp(200, headers={})})
    findings = [f for f in _collect(_ctx(url, http))
                if f.rule_id == "dast.cookies.missing-secure"]
    assert len(findings) == 1
    assert findings[0].location.url == url      # located on the hop that set it


def test_the_tls_probe_follows_an_http_entry_to_its_https_landing(monkeypatch):
    """An http:// URL that redirects to https:// is what a correctly configured
    site looks like, and it took the plain-HTTP skip: the certificate the
    operator wanted checked was one hop away and the report said there was none
    to read."""
    url = "http://example.com/"
    landing = "https://example.com/"
    http = _FakeHttp(url, _redirect(landing),
                     by_url={landing: _Resp(200, headers={})})
    seen = {}

    async def fake_fetch(u, gate, **kwargs):
        seen["url"] = u
        return _expired_cert(), "TLSv1.3"

    monkeypatch.setattr(dast_scanner, "fetch_tls", fake_fetch)
    ctx = _ctx(url, http, tls=True)
    ids = {f.rule_id for f in _collect(ctx)}
    assert seen["url"] == landing
    assert "dast.tls.expired-cert" in ids
    assert [s for s in ctx.skipped if s.check == "tls"] == []


def test_an_https_entry_landing_on_http_still_reads_the_certificate_it_used(monkeypatch):
    """That handshake happened and its certificate is real, so the probe keeps the
    entry URL rather than skipping because the chain ended in plaintext."""
    url = "https://example.com/"
    landing = "http://example.com/insecure"
    http = _FakeHttp(url, _redirect(landing),
                     by_url={landing: _Resp(200, headers={})})
    seen = {}

    async def fake_fetch(u, gate, **kwargs):
        seen["url"] = u
        return _expired_cert(), "TLSv1.3"

    monkeypatch.setattr(dast_scanner, "fetch_tls", fake_fetch)
    ids = {f.rule_id for f in _collect(_ctx(url, http, tls=True))}
    assert seen["url"] == url
    assert "dast.tls.expired-cert" in ids


def test_a_site_that_is_plain_http_throughout_says_where_it_ended_up():
    url = "http://example.com/"
    landing = "http://example.com/home"
    http = _FakeHttp(url, _redirect("/home"),
                     by_url={landing: _Resp(200, headers={})})
    ctx = _ctx(url, http, tls=True)
    _collect(ctx)
    tls = [s for s in ctx.skipped if s.check == "tls"]
    assert len(tls) == 1
    assert landing in tls[0].reason


def test_the_exposed_file_probe_follows_the_redirect_to_the_real_origin():
    """`probe_exposed_files` appends paths to an origin. A scan of example.com
    that lands on www.example.com was asking the wrong host for /.env, getting a
    3xx for every probe -- which is not a hit -- and reporting nothing exposed."""
    url = "https://example.com/"
    landing = "https://www.example.com/"
    http = _FakeHttp(url, _redirect(landing), by_url={
        landing: _Resp(200, headers={}),
        "https://www.example.com/.env": _Resp(200, "API_KEY=abc\n"),
    })
    ids = {f.rule_id for f in _collect(_ctx(url, http, subdomains=True))}
    assert "dast.exposed.env-file" in ids
    assert "https://example.com/.env" not in http.gets


def test_exposed_probes_that_never_completed_are_errors_not_a_clean_result():
    """The wiring, not the probe. `probe_exposed_files` now hands back the probes it
    could not complete, and that is worth nothing unless the caller puts them on the
    same channel a crash uses -- these have to reach the report and push the run to
    exit 3, because this check answers by finding nothing and an unreachable host
    would otherwise render exactly like a secured one (D66)."""
    class _DeadProbes(_FakeHttp):
        async def get(self, url, **kwargs):
            if url == self.entry_url:
                return await super().get(url, **kwargs)
            raise OSError("[Errno 111] Connection refused")

    url = "https://example.com/"
    ctx = _ctx(url, _DeadProbes(url, _Resp(200, headers={})))
    _collect(ctx)
    exposed = [e for e in ctx.errors if e.check == "exposed"]
    # Three probe paths plus the calibration fetch.
    assert len(exposed) == 4, [e.message for e in exposed]
    assert all("Connection refused" in e.message for e in exposed)
    assert sum("calibration-failed" in e.message for e in exposed) == 1


def test_no_http_client_makes_the_exposed_probe_skip_rather_than_fail_four_times():
    """A missing client is not four dead probes, it is a check that never ran -- the
    same distinction the TLS probe beside it already draws, and the reason `skipped`
    and `errors` are separate channels."""
    url = "https://example.com/"
    ctx = _ctx(url, _FakeHttp(url, _Resp(200, headers={})))
    ctx.http = None
    _collect(ctx)
    assert [s.check for s in ctx.skipped if s.check == "exposed"] == ["exposed"]
    assert [e for e in ctx.errors if e.check == "exposed"] == []


def test_a_broken_redirect_on_the_entry_url_is_an_error_not_a_silent_stub():
    """All that can be graded is the stub, so the findings are about the stub --
    and the report has to say so, because a 302 with no Location means the page
    the operator asked about was never read at all."""
    url = "https://example.com/"
    http = _FakeHttp(url, _Resp(302, "", headers={}))
    ctx = _ctx(url, http)
    _collect(ctx)
    broken = [e for e in ctx.errors if e.scanner == "dast" and e.check == "response"]
    assert len(broken) == 1
    assert "redirect-broken" in broken[0].message


def test_a_redirect_out_of_scope_is_reported_by_the_passive_tier_too():
    url = "https://example.com/"
    http = _FakeHttp(url, _redirect("https://tracker.elsewhere.com/"))
    ctx = _ctx(url, http)
    _collect(ctx)
    assert "https://tracker.elsewhere.com/" not in http.gets
    out = [e for e in ctx.errors if e.check == "response"]
    assert len(out) == 1
    assert "redirect-out-of-scope" in out[0].message
    assert "tracker.elsewhere.com" in out[0].message
