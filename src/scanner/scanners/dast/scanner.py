"""The DAST passive scanner (``dast``): observe one live response, plus a little
in-bounds recon.

The passive tier never sends an attack payload. It fetches the entry URL once and
inspects what any ordinary client would already receive — security headers,
``Set-Cookie`` attributes, version-leaking headers — then layers on two light,
same-origin probes: TLS certificate inspection and a curated exposed-file check
(contract §12). The intrusive request-mutating work lives in the separate
``dast-active`` scanner behind the triple gate; nothing here mutates a request.

Each sub-check runs through :meth:`ScanContext.run_check`, so one failure (an
unreachable host, a TLS handshake error, a probe timeout) is recorded as a
``ScanError`` and isolated — it never sinks the other checks. Every DAST finding
carries ``fix=None``: a live application has no file for us to patch (contract §7).
"""

from __future__ import annotations

from scanner.core.finding import Finding
from scanner.core.registry import register
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.dast.cookies import check_cookies
from scanner.scanners.dast.exposed import probe_exposed_files
from scanner.scanners.dast.fingerprint import check_fingerprint
from scanner.scanners.dast.headers import check_security_headers
from scanner.scanners.dast.tls import analyze_tls, fetch_tls, now_utc


@register
class DastScanner(Scanner):
    name = "dast"
    requires = Requires(url=True)

    async def scan(self, ctx):
        if not ctx.target.has_web:
            ctx.emit_skip("dast", "the target has no URL to observe")
            return
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.enabled", True):
            ctx.emit_skip("dast", "switched off by config: dast.enabled = false")
            return
        url = ctx.target.url
        findings: list[Finding] = []
        findings += await ctx.run_check("dast", "response", self._response_checks(ctx, url))
        findings += await ctx.run_check("dast", "tls", self._tls_check(ctx, url))
        findings += await ctx.run_check("dast", "exposed", self._exposed_check(ctx, url))
        for finding in findings:
            yield finding

    async def _response_checks(self, ctx, url: str) -> list[Finding]:
        """Header, fingerprint and cookie findings from a single GET of the entry
        URL. These signals are site-uniform, so the entry page is representative."""
        resp = await ctx.http.get(url)
        headers = resp.headers
        set_cookies = headers.get_list("set-cookie")
        return (
            check_security_headers(url, headers)
            + check_fingerprint(url, headers)
            + check_cookies(url, set_cookies)
        )

    async def _tls_check(self, ctx, url: str) -> list[Finding]:
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.tls.enabled", True):
            ctx.emit_skip(
                "dast", "switched off by config: dast.tls.enabled = false", check="tls",
            )
            return []
        if not url.lower().startswith("https://"):
            ctx.emit_skip(
                "dast", "the target is plain HTTP, so there is no certificate to read",
                check="tls",
            )
            return []
        if ctx.http is None:
            # No client means no gate to authorize the raw socket through.
            ctx.emit_skip(
                "dast", "no HTTP client was wired, so the certificate probe has no "
                "gate to authorize through", check="tls",
            )
            return []
        # The probe skips the HTTP choke point, so it is handed that client's own
        # gate and authorizes through it (contract §9). Same boundary, one owner.
        result = await fetch_tls(url, ctx.http.gate)
        if result is None:
            return []
        cert, protocol = result
        return analyze_tls(url, cert, protocol, now_utc())

    async def _exposed_check(self, ctx, url: str) -> list[Finding]:
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.exposed.enabled", True):
            ctx.emit_skip(
                "dast", "switched off by config: dast.exposed.enabled = false",
                check="exposed",
            )
            return []
        return await probe_exposed_files(url, ctx.http)
