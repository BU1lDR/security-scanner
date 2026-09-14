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


class _FakeHttp:
    def __init__(self, entry_url, entry_resp, by_path=None, raise_entry=False):
        self.entry_url = entry_url
        self.entry_resp = entry_resp
        self.by_path = by_path or {}
        self.raise_entry = raise_entry
        # The real client carries the gate the TLS probe has to authorize through,
        # so a double that omits it would hide the wiring this fake is here to test.
        self.gate = RequestGate(Scope.from_url(entry_url), Egress())

    async def get(self, url, **kwargs):
        if url == self.entry_url:
            if self.raise_entry:
                raise RuntimeError("connection refused")
            return self.entry_resp
        for path, resp in self.by_path.items():
            if url.endswith(path):
                return resp
        return _Resp(404, "not found")


def _ctx(url, http, *, tls=False):
    target = Target(url=url)
    cfg = Config.from_dict({"dast": {"tls": {"enabled": tls}}})
    return ScanContext(target=target, scope=target.scope, http=http, config=cfg)


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
