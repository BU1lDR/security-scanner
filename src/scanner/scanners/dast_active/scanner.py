"""The DAST active scanner (``dast-active``): crawl, bridge, inject (contract §12).

Flow: passively crawl the in-scope site into ``Page``/``Form`` records, transform
those into :class:`InjectionPoint`s (the crawler→active bridge), then run each
enabled detection-only check against each point. Every check request carries
``active=True`` so the choke point re-applies the fail-closed triple gate — this
scanner never bypasses it.

Selection is gated by the engine (contract §11: ``--active`` + ``--i-am-authorized``
+ the host in ``scope.active_allowlist``). As defence in depth we *also* refuse to
run unless ``dast.active.enabled`` is set, so a mis-wired caller can never trip an
active scan silently.

Isolation and bounding: the crawl and every (check, point) run are fault-isolated
(one crash is recorded, the rest continue), and total active traffic is capped by
``dast.active.max_requests`` — when the budget is reached we stop and log how many
checks were skipped rather than silently pretending the surface was fully covered.

Fault-isolated is not the same as silent, and this scanner is where the difference
matters most. What it could not read, it records: pages the crawl failed to fetch
become ``ScanError``s so the run exits 3 rather than 0, and hosts the request gate
refused become ``ScanSkip``s so "we were not allowed to test that" is told apart
from "we tested it and it was fine" (D58, D59).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from scanner.core.finding import Finding
from scanner.core.gate import OutOfScopeError
from scanner.core.registry import register
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.dast.crawler import INCOMPLETE_KINDS, CrawlResult, crawl
from scanner.scanners.dast_active.checks import ALL_CHECKS
from scanner.scanners.dast_active.injection import injection_points


class _CountingHttp:
    """Wraps the shared client to count active-check requests against the budget.
    Delegates transparently; adds nothing but a tally."""

    def __init__(self, http) -> None:
        self._http = http
        self.count = 0

    async def get(self, *args, **kwargs):
        self.count += 1
        return await self._http.get(*args, **kwargs)

    async def post(self, *args, **kwargs):
        self.count += 1
        return await self._http.post(*args, **kwargs)


@register
class DastActiveScanner(Scanner):
    name = "dast-active"
    requires = Requires(url=True, active=True)

    async def scan(self, ctx):
        if not ctx.target.has_web:
            ctx.emit_skip("dast-active", "the target has no URL to probe")
            return
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.active.enabled", False):
            ctx.emit_skip(
                "dast-active",
                "switched off by config: dast.active.enabled is not set, so no "
                "attack-shaped request was sent",
            )
            return

        crawl_result = await self._safe_crawl(ctx)
        include_post = bool(cfg.get("dast.active.include_post", False)) if cfg else False
        points = injection_points(crawl_result, include_post=include_post)
        checks = self._selected_checks(cfg)
        max_requests = int(cfg.get("dast.active.max_requests", 200)) if cfg else 200

        counted = _CountingHttp(ctx.http)
        skipped = 0
        refused: dict[str, int] = {}
        for point in points:
            for name, check in checks.items():
                if counted.count >= max_requests:
                    skipped += 1
                    continue
                for finding in await ctx.run_check(
                    "dast-active", f"{name}",
                    self._check_unless_refused(check(point, counted), point, refused),
                ):
                    yield finding
        if skipped:
            ctx.logger.warning(
                "dast-active: request budget (%d) reached; %d (point, check) "
                "combinations were not run.", max_requests, skipped,
            )
            ctx.emit_skip(
                "dast-active",
                f"the request budget (dast.active.max_requests = {max_requests}) was "
                f"reached, so {skipped} (injection point, check) combinations were "
                f"not run",
                check="budget",
            )
        for host, count in sorted(refused.items()):
            ctx.emit_skip(
                "dast-active",
                f"{count} checks were not run against {host}: the request gate "
                f"refused them, so that host was crawled but never tested",
                check="gate",
            )

    @staticmethod
    async def _check_unless_refused(coro, point, refused: dict[str, int]):
        """Await one check, telling a refusal apart from a failure.

        A gate refusal is not a crash and must not be recorded as one: it means this
        host is in scope to look at but not in ``scope.active_allowlist``, which is a
        deliberate configuration and would put every such run at exit 3. It is not
        nothing either — before this, ``_send`` swallowed the ``OutOfScopeError`` and
        the check read the missing response as a clean negative, so a host the
        operator had deliberately excluded from testing appeared in the report as a
        host that had been tested and found sound. It is a skip, tallied per host and
        emitted once. Every other exception propagates to ``run_check``.
        """
        try:
            return await coro
        except OutOfScopeError:
            host = urlsplit(point.url).hostname or point.url
            refused[host] = refused.get(host, 0) + 1
            return []

    async def _safe_crawl(self, ctx) -> CrawlResult:
        try:
            cfg = ctx.config
            c = (cfg.get("dast.crawler", {}) if cfg else {}) or {}
            result = await crawl(
                ctx.target.url,
                ctx.http,
                ctx.scope,
                max_depth=int(c.get("max_depth", 2)),
                max_pages=int(c.get("max_pages", 50)),
                # allow_subdomains is deliberately absent: it is carried by
                # ctx.scope, which the crawl and the request gate both consult.
            )
        except Exception as exc:  # noqa: BLE001 - a failed crawl must not sink the scan
            ctx.emit_error("dast-active", "crawl", exc)
            return CrawlResult()
        self._record_crawl_problems(ctx, result)
        return result

    @staticmethod
    def _record_crawl_problems(ctx, result: CrawlResult) -> None:
        """Turn what the crawl could not read into report entries.

        The crawl walks past its own failures by design — one dead link must not sink
        the rest — and that is only defensible if walking past them is recorded. A
        page that refused, timed out or 5xx'd narrows the surface the active tier can
        test, and an injection point that was never discovered cannot produce a
        finding, so the report would otherwise describe a smaller site as a cleaner
        one. Those become errors, which is what moves the exit code to 3.

        A 4xx is logged and no more. Dead links are ordinary on real sites, and an
        exit code that fires on all of them carries no information.
        """
        for problem in result.problems:
            if problem.kind in INCOMPLETE_KINDS:
                ctx.emit_failure(
                    "dast-active", "crawl",
                    f"{problem.kind}: {problem.url} — {problem.detail}",
                )
            else:
                ctx.logger.info(
                    "dast-active: crawl skipped %s (%s: %s)",
                    problem.url, problem.kind, problem.detail,
                )

    @staticmethod
    def _selected_checks(cfg):
        names = cfg.get("dast.active.checks", []) if cfg else []
        if not names:
            return dict(ALL_CHECKS)
        return {n: ALL_CHECKS[n] for n in names if n in ALL_CHECKS}
