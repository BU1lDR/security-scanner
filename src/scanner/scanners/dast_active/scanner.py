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
"""

from __future__ import annotations

from scanner.core.finding import Finding
from scanner.core.registry import register
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.dast.crawler import CrawlResult, crawl
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
            return
        cfg = ctx.config
        if cfg is not None and not cfg.get("dast.active.enabled", False):
            return

        crawl_result = await self._safe_crawl(ctx)
        include_post = bool(cfg.get("dast.active.include_post", False)) if cfg else False
        points = injection_points(crawl_result, include_post=include_post)
        checks = self._selected_checks(cfg)
        max_requests = int(cfg.get("dast.active.max_requests", 200)) if cfg else 200

        counted = _CountingHttp(ctx.http)
        skipped = 0
        for point in points:
            for name, check in checks.items():
                if counted.count >= max_requests:
                    skipped += 1
                    continue
                for finding in await ctx.run_check(
                    "dast-active", f"{name}", check(point, counted)
                ):
                    yield finding
        if skipped:
            ctx.logger.warning(
                "dast-active: request budget (%d) reached; %d (point, check) "
                "combinations were not run.", max_requests, skipped,
            )

    async def _safe_crawl(self, ctx) -> CrawlResult:
        try:
            cfg = ctx.config
            c = (cfg.get("dast.crawler", {}) if cfg else {}) or {}
            return await crawl(
                ctx.target.url,
                ctx.http,
                ctx.scope,
                max_depth=int(c.get("max_depth", 2)),
                max_pages=int(c.get("max_pages", 50)),
                allow_subdomains=bool(c.get("allow_subdomains", False)),
            )
        except Exception as exc:  # noqa: BLE001 - a failed crawl must not sink the scan
            ctx.emit_error("dast-active", "crawl", exc)
            return CrawlResult()

    @staticmethod
    def _selected_checks(cfg):
        names = cfg.get("dast.active.checks", []) if cfg else []
        if not names:
            return dict(ALL_CHECKS)
        return {n: ALL_CHECKS[n] for n in names if n in ALL_CHECKS}
