"""The DAST passive scanner (``dast``): observe one live response, plus a little
in-bounds recon.

The passive tier never sends an attack payload. It fetches the entry URL, follows it
to wherever a client would land, and inspects what any ordinary client would already
receive — security headers, ``Set-Cookie`` attributes, version-leaking headers — then
layers on two light, same-origin probes: TLS certificate inspection and a curated
exposed-file check (contract §12). The intrusive request-mutating work lives in the
separate ``dast-active`` scanner behind the triple gate; nothing here mutates a
request.

"Wherever a client would land" is the whole of D62 in this file. Every check here used
to be pointed at the entry URL's own response, and when that response was a redirect
the tier graded the stub: a missing Content-Security-Policy reported against a body
that has no document to protect, a missing X-Frame-Options against nothing framable,
and the response that should have carried either one never read. The TLS check was
worse than inaccurate — it skipped on a plain-HTTP entry URL, which is exactly the
one that redirects to HTTPS, so the ordinary ``http://`` invocation of a correctly
configured site inspected no certificate at all and said only that there was none.

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
from scanner.scanners.dast.redirects import follow, set_cookies
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
        # Filled in by the response check as it walks the chain. Passed in rather
        # than returned because `run_check` hands back findings and swallows the
        # exception, and a chain that broke on hop three still tells the two probes
        # below more about where they are than the entry URL does.
        chain: list[tuple[str, object]] = []
        findings += await ctx.run_check(
            "dast", "response", self._response_checks(ctx, url, chain),
        )
        landing = chain[-1][0] if chain else url
        findings += await ctx.run_check("dast", "tls", self._tls_check(ctx, url, landing))
        findings += await ctx.run_check("dast", "exposed", self._exposed_check(ctx, landing))
        for finding in findings:
            yield finding

    async def _response_checks(self, ctx, url: str, chain: list) -> list[Finding]:
        """Header, fingerprint and cookie findings from the response a client lands
        on, and cookies from every response on the way there.

        Headers and fingerprints are graded on the landing response only. The old
        comment here said these signals are "site-uniform, so the entry page is
        representative", which is true of a page and false of a redirect: a 302 is
        not a smaller sample of the site, it is a different kind of response, and the
        headers a proxy attaches to one say nothing about the document behind it.

        Cookies are graded on every hop, because a ``Set-Cookie`` on a redirect is the
        ordinary shape of a login and a session cookie missing ``HttpOnly`` is no less
        exposed for having arrived on a response with no body. Checked per hop rather
        than as one pooled list so each finding's location names the response that
        actually set it — contract §8 keys the dedup on location, so pooling them
        would collapse two insecure cookies from two hops into one.
        """
        hops, problems = await follow(url, ctx.http, ctx.scope)
        chain.extend(hops)
        for hop_url, kind, detail in problems:
            # emit_failure, not a log: a redirect we declined to follow means the
            # headers below were graded on a stub, which is the one thing about this
            # report that would otherwise read as a finished answer.
            ctx.emit_failure("dast", "response", f"{kind}: {hop_url} — {detail}")
        landing_url, landing = hops[-1]
        return (
            check_security_headers(landing_url, landing.headers)
            + check_fingerprint(landing_url, landing.headers)
            + [f for hop_url, resp in hops
               for f in check_cookies(hop_url, set_cookies(resp))]
        )

    async def _tls_check(self, ctx, url: str, landing: str) -> list[Finding]:
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.tls.enabled", True):
            ctx.emit_skip(
                "dast", "switched off by config: dast.tls.enabled = false", check="tls",
            )
            return []
        # Whichever end of the chain was reached over TLS, preferring the one a
        # client ends up on. An `http://` entry URL that redirects to HTTPS is the
        # normal configuration of a site that has done this right, and it used to
        # take the skip below: the certificate the operator wanted checked was one
        # redirect away and the report said there was none to read. The reverse —
        # HTTPS entry landing on plain HTTP — keeps the entry URL, because that
        # handshake happened and its certificate is real.
        probe_url = next(
            (u for u in (landing, url) if u.lower().startswith("https://")), "",
        )
        if not probe_url:
            hop = "" if landing == url else f" (and followed it to {landing})"
            ctx.emit_skip(
                "dast", "the target is plain HTTP, so there is no certificate to "
                f"read{hop}",
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
        result = await fetch_tls(probe_url, ctx.http.gate)
        if result is None:
            return []
        cert, protocol = result
        return analyze_tls(probe_url, cert, protocol, now_utc())

    async def _exposed_check(self, ctx, url: str) -> list[Finding]:
        """Probe for files that should not be public, at the origin we landed on.

        The landing URL, not the entry URL: ``probe_exposed_files`` derives an origin
        and appends paths to it, and a scan of ``http://example.com`` that lands on
        ``https://www.example.com`` was asking the wrong origin for ``/.git/config``.
        Every one of those probes came back 3xx, which is not a hit, so the check
        reported nothing found — a clean result for a host it never examined.
        """
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.exposed.enabled", True):
            ctx.emit_skip(
                "dast", "switched off by config: dast.exposed.enabled = false",
                check="exposed",
            )
            return []
        return await probe_exposed_files(url, ctx.http)
