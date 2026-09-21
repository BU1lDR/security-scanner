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
``dast.active.max_requests``. The cap is enforced by the object that counts the
requests, not by the loop that starts the checks, because a check may send more
than one — a budget that is checked once per check and then walked past is not a
budget (D61). Whatever it stops is disclosed rather than merely logged, because the
findings list of a scan that tested a tenth of the surface is shaped exactly like
the findings list of a scan that tested all of it and liked what it saw.

Fault-isolated is not the same as silent, and this scanner is where the difference
matters most. What it could not read, it records: pages the crawl failed to fetch
become ``ScanError``s so the run exits 3 rather than 0, and hosts the request gate
refused become ``ScanSkip``s so "we were not allowed to test that" is told apart
from "we tested it and it was fine" (D58, D59).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from scanner.core.finding import Finding
from scanner.core.gate import OutOfScopeError
from scanner.core.registry import register
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.dast.crawler import INCOMPLETE_KINDS, CrawlResult, crawl
from scanner.scanners.dast_active.checks import ALL_CHECKS
from scanner.scanners.dast_active.injection import injection_points


class _BudgetReached(Exception):
    """Raised *instead of* sending the request that would exceed the budget.

    Deliberately not an :class:`OutOfScopeError`: this is the scanner declining to
    send, where that is the operator declining. They are disclosed differently
    because the reader's next action differs — one is a bound they can raise, the
    other is a permission they chose not to give.
    """


@dataclass
class _Incomplete:
    """What the active tier got no verdict on, kept separated by why.

    A refusal and a budget cut-off are both "this parameter was never actually
    tested", and both would otherwise land in the report as an absence of findings.
    They are counted apart because the two sentences are not interchangeable: one
    says a host was kept out of the active allowlist, the other says the scan ran
    out of the traffic it was allowed to send.
    """

    refused: dict[str, int] = field(default_factory=dict)
    cut_off: int = 0


class _CountingHttp:
    """The active tier's request budget, enforced where the requests are counted.

    Two separate things were wrong with enforcing it anywhere else.

    The tally was incremented *before* delegating, so a probe the request gate
    refused — one that never reached a socket — spent budget that exists to bound
    what the *target* receives. A host that was in scope to crawl but absent from
    ``scope.active_allowlist`` could therefore exhaust a 200-request budget having
    sent nothing at all, and the report then carried "the request budget was
    reached" beside an active-request count of zero, which cannot both be true.

    And the ceiling was tested once per (point, check) pair rather than once per
    request, so a check that sends two of them — ``sqli-error`` sends an untampered
    baseline and then the probe — was cleared against the limit and then walked past
    it. That is D58's rule one layer in: the number has to be kept by the thing that
    does the sending, or it is a description of intent rather than a bound.
    """

    def __init__(self, http, max_requests: int) -> None:
        self._http = http
        self.max_requests = max_requests
        self.count = 0

    async def get(self, *args, **kwargs):
        return await self._charge(self._http.get, *args, **kwargs)

    async def post(self, *args, **kwargs):
        return await self._charge(self._http.post, *args, **kwargs)

    async def _charge(self, send, *args, **kwargs):
        if self.count >= self.max_requests:
            raise _BudgetReached(
                f"dast.active.max_requests = {self.max_requests} reached"
            )
        try:
            result = await send(*args, **kwargs)
        except OutOfScopeError:
            # Refused at the choke point, so nothing was sent and nothing is
            # charged. Charging it would let a host we are not allowed to probe
            # consume the budget for the hosts we are.
            raise
        except Exception:
            # It went out and never came back. The target received it, so it is
            # still traffic: an unanswered probe must not buy a free one.
            self.count += 1
            raise
        self.count += 1
        return result


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
        checks = self._selected_checks(ctx, cfg)
        max_requests = int(cfg.get("dast.active.max_requests", 200)) if cfg else 200

        counted = _CountingHttp(ctx.http, max_requests)
        incomplete = _Incomplete()
        for point in points:
            for name, check in checks.items():
                # No budget test here. Every check is started and the counter turns
                # the ones it cannot afford away, which costs an iteration and buys
                # an accurate number: a check that needs no request (open-redirect
                # on a parameter that is not URL-shaped) still reaches its correct
                # verdict after the budget is gone, and is not counted as a gap.
                for finding in await ctx.run_check(
                    "dast-active", f"{name}",
                    self._guarded(check(point, counted), point, incomplete),
                ):
                    yield finding
        if incomplete.cut_off:
            ctx.logger.warning(
                "dast-active: request budget (%d) reached; %d (point, check) "
                "combinations were not completed.", max_requests, incomplete.cut_off,
            )
            ctx.emit_skip(
                "dast-active",
                f"the request budget (dast.active.max_requests = {max_requests}) was "
                f"reached, so {incomplete.cut_off} (injection point, check) "
                f"combinations were not completed",
                check="budget",
            )
        for host, count in sorted(incomplete.refused.items()):
            ctx.emit_skip(
                "dast-active",
                f"{count} checks were not run against {host}: the request gate "
                f"refused them, so that host was crawled but never tested",
                check="gate",
            )

    @staticmethod
    async def _guarded(coro, point, incomplete: _Incomplete):
        """Await one check, telling the two deliberate non-answers apart from a crash.

        A gate refusal is not a crash and must not be recorded as one: it means this
        host is in scope to look at but not in ``scope.active_allowlist``, which is a
        deliberate configuration and would put every such run at exit 3. It is not
        nothing either — before this, ``_send`` swallowed the ``OutOfScopeError`` and
        the check read the missing response as a clean negative, so a host the
        operator had deliberately excluded from testing appeared in the report as a
        host that had been tested and found sound. It is a skip, tallied per host and
        emitted once.

        A budget cut-off is the same shape for the same reason: this parameter was not
        tested, and the bound that stopped it is one the operator set and can raise.
        Both are counted, neither is an error, and every other exception propagates to
        ``run_check``, which is what turns a genuine failure into exit 3.
        """
        try:
            return await coro
        except OutOfScopeError:
            host = urlsplit(point.url).hostname or point.url
            incomplete.refused[host] = incomplete.refused.get(host, 0) + 1
            return []
        except _BudgetReached:
            incomplete.cut_off += 1
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
                user_agent=c.get("user_agent") or None,
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
    def _selected_checks(ctx, cfg):
        """The checks to run, saying so when a requested name selected nothing.

        ``Config.load`` already rejects an unknown name against a closed set, with a
        did-you-mean, and that is where the fix for this belongs: a config file cannot
        reach the filter below. This is the second line, for the callers
        ``Config.from_dict`` is deliberately lenient for. The filter keeps the
        intersection, so a name matching nothing narrows the tier with no word said —
        and when it was the only name, the tier runs zero checks, the engine reports
        dast-active as having run, and an empty findings list reads as a clean target.
        Of all the ways this particular mistake could fail, that is the worst
        direction (D42), so the narrowing is disclosed even though nothing reachable
        from ``argv`` can cause it.
        """
        names = list(cfg.get("dast.active.checks", []) or []) if cfg else []
        if not names:
            return dict(ALL_CHECKS)
        selected = {n: ALL_CHECKS[n] for n in names if n in ALL_CHECKS}
        unknown = [str(n) for n in names if n not in ALL_CHECKS]
        if unknown:
            ran = f"only {', '.join(selected)} ran" if selected else \
                "no active check ran at all"
            ctx.emit_skip(
                "dast-active",
                f"dast.active.checks named {len(unknown)} check(s) that do not "
                f"exist ({', '.join(sorted(unknown))}), so {ran}",
                check="checks",
            )
        return selected
