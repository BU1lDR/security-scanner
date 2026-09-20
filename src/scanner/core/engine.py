"""The coordinator: select scanners, run them, de-duplicate, report.

The engine reads each registered scanner's :class:`~scanner.core.scanner.Requires`
to decide which apply to the target, applies the fail-closed active-check gate
(contract §11), runs the selected scanners, and collapses duplicate findings by
fingerprint (contract §8). It returns a :class:`ScanReport` carrying the surviving
findings and any recorded scan errors.

v1 runs scanners sequentially; concurrency across scanners (sharing the one
rate-limited client) is a later optimization. Fault isolation lives in each
scanner via ``ctx.run_check`` (contract §10), so the engine does not need to wrap
individual checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.core.context import ScanContext, ScanError, ScanSkip
from scanner.core.finding import Finding, Severity
from scanner.core.registry import Registry
from scanner.core.registry import registry as default_registry
from scanner.core.target import Target


def _sent(http: object) -> tuple[int, int] | None:
    """``(total, active)`` requests the HTTP choke point has sent, or ``None``.

    ``None`` means the client does not keep the counters — a test double, or no
    client at all — and is deliberately distinct from ``(0, 0)``, which is the
    client saying it sent nothing. Callers must not collapse the two: one is "we
    did not observe", the other is "we observed no traffic", and this whole
    mechanism exists because those were once the same value.
    """
    total = getattr(http, "requests_sent", None)
    active = getattr(http, "active_requests_sent", None)
    if not isinstance(total, int) or not isinstance(active, int):
        return None
    return total, active


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a fingerprint, keeping the strongest.

    "Strongest" is the higher ``(severity, confidence)`` tuple. This picks the
    stronger of two real findings; it never raises a single finding's own
    confidence beyond what its scanner reported (contract §8)."""
    best: dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        current = best.get(key)
        if current is None or (f.severity, f.confidence) > (
            current.severity,
            current.confidence,
        ):
            best[key] = f
    return list(best.values())


@dataclass
class ScanReport:
    findings: list[Finding]
    errors: list[ScanError] = field(default_factory=list)

    #: Names of the scanners that actually ran, in selection order.
    #:
    #: A report used to say only what was *found*. What was *done* was not
    #: recorded anywhere, and for the intrusive tier that is the more important
    #: of the two. Measured before this existed: a config file with
    #: ``dast.active.enabled`` and ``scope.authorized_ack`` set sends injection
    #: payloads, traversal strings and probe requests to the target while the
    #: command is a bare ``secscan https://host/`` — no flag in shell history, no
    #: line on stderr, and nothing in the report. An active scan that happened to
    #: find nothing was indistinguishable from a passive one.
    #:
    #: That matters because of what this report is *for*. The README says
    #: unauthorized scanning is illegal in most jurisdictions; the report is the
    #: artifact you keep to show what you did to a host and when. A record of
    #: findings alone cannot answer the only question that would ever be asked of
    #: it, which is whether you attacked the machine or just looked at it.
    #:
    #: Default empty so a hand-built ScanReport (tests, fixtures) stays valid.
    #: Renderers show the line only when the list is populated, so an empty one
    #: reads as "not recorded" rather than as "nothing ran".
    #:
    #: A scanner that declined outright is *not* here — it is in :attr:`skipped`
    #: instead. This list used to be the selection verbatim, which meant a
    #: ``dast.active.enabled = false`` in a config file produced a report saying
    #: ``Ran: dast, dast-active`` about a scanner that returned on its first line.
    scanners_run: list[str] = field(default_factory=list)

    #: The subset of :attr:`scanners_run` that *was observed sending* attack-shaped
    #: traffic: an active scanner appears here only if the request counters at the
    #: choke point moved while it was running.
    #:
    #: It used to be the active subset of the selection, and that was the one field
    #: in the report where being quietly wrong is worst. Measured: a target on a
    #: bound-but-not-listening port exits 3 having sent no probe at all (the crawl
    #: finds no pages, so there are no injection points and no check runs), and the
    #: report still announced "ACTIVE CHECKS RAN. This scan sent attack-shaped
    #: requests to the target." Selection is intent; this section is a record of
    #: what was done, and only the choke point knows that.
    #:
    #: Still keyed off ``cls.requires.active`` rather than a ``-active`` name
    #: suffix — that flag is what the gate itself reads, and a name-based guess
    #: would be a second, weaker definition of "intrusive" a rename could falsify.
    #: When no counting client is wired (a unit test with a fake, or no client at
    #: all) an active scanner that ran is listed, because the fallback has to err
    #: towards over-disclosure: claiming traffic we did not send is a nuisance,
    #: while missing traffic we did send is the failure this field guards against.
    active_scanners_run: list[str] = field(default_factory=list)

    #: Work that was selected and then declined, and why (see :class:`ScanSkip`).
    #: Not a failure: it does not touch :meth:`exit_code`. It exists so that
    #: "switched off" is legible in a report instead of looking like "found
    #: nothing", which is the same conflation D42 named one level up.
    skipped: list[ScanSkip] = field(default_factory=list)

    #: Requests the choke point sent, in total and active-only. ``None`` means no
    #: counting client was wired, which is not the same as zero (see :func:`_sent`).
    #: These are the evidence behind :attr:`active_scanners_run`; they are reported
    #: as well as used, because a disclosure that cannot be checked is a claim.
    requests_sent: int | None = None
    active_requests_sent: int | None = None

    @property
    def sent_active_traffic(self) -> bool:
        return bool(self.active_scanners_run)

    def exit_code(self, threshold: Severity) -> int:
        """0 = clean, 1 = a finding at or above ``threshold``, 3 = the scan ran but
        some check recorded an error (D54). (Exit code 2 is reserved for
        engine-level failure and is decided at the CLI, D14.)

        ``errors`` used to be ignored here, so a scan whose checks died produced
        an empty finding list and exited 0 — indistinguishable from a target that
        was genuinely clean. That is the conflation D42 and D46 named: "we found
        nothing" and "we could not look" must not be the same output.

        **A finding at or above the threshold outranks an incomplete scan.** Both
        fail a build, so the only question is which fact the one scalar carries,
        and this ordering is deliberate rather than incidental: ``errors`` is
        ungraded in both directions — it holds a transient 429 and a crashed rule
        pack alike, and an empty list does not mean complete (see D54 for the two
        measured gaps) — so letting it displace a specific, verified finding would
        trade a precise fact for a vague one. The cost is real and is accepted: on
        a scan that has findings, an error's incompleteness reaches the report
        body but not the exit code. D54 records why that is the better trade and
        what grading ``ScanError`` would let us revisit.
        """
        if any(f.severity >= threshold for f in self.findings):
            return 1
        if self.errors:
            return 3
        return 0


class Engine:
    def __init__(self, registry: Registry | None = None) -> None:
        self.registry = registry if registry is not None else default_registry

    def select(self, target: Target, *, active_enabled: bool = False) -> list[type]:
        """Applicable scanners, with active scanners gated fail-closed."""
        selected: list[type] = []
        for cls in self.registry.applicable(target):
            if cls.requires.active:
                if not active_enabled:
                    continue
                if not (target.url and target.scope.active_allowed(target.url)):
                    continue
            selected.append(cls)
        return selected

    async def run(
        self,
        target: Target,
        *,
        active_enabled: bool = False,
        http: object = None,
        config: object = None,
    ) -> ScanReport:
        ctx = ScanContext(
            target=target,
            scope=target.scope,
            http=http,
            config=config,
        )
        collected: list[Finding] = []
        selected = self.select(target, active_enabled=active_enabled)
        ran: list[str] = []
        active_ran: list[str] = []
        for cls in selected:
            before = _sent(ctx.http)
            skips_before = len(ctx.skipped)
            scanner = cls()
            async for finding in scanner.scan(ctx):
                collected.append(finding)
            after = _sent(ctx.http)
            # A whole-scanner skip (empty `check`) means it declined before doing
            # anything, so it does not go in the "Ran:" line. A skip naming a check
            # is one part of a scanner that did run, and belongs beside it.
            if any(s.scanner == cls.name and not s.check for s in ctx.skipped[skips_before:]):
                continue
            ran.append(cls.name)
            # Not "it was selected" but "the counters moved while it was running".
            # Unobserved falls back to listing it, which over-discloses rather than
            # under-discloses — see the field's own note.
            if cls.requires.active and (
                before is None or after is None or after[1] > before[1]
            ):
                active_ran.append(cls.name)
        final = _sent(ctx.http)
        return ScanReport(
            findings=dedupe(collected),
            errors=ctx.errors,
            scanners_run=ran,
            active_scanners_run=active_ran,
            skipped=ctx.skipped,
            requests_sent=final[0] if final is not None else None,
            active_requests_sent=final[1] if final is not None else None,
        )
