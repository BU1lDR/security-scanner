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

from scanner.core.context import ScanContext, ScanError
from scanner.core.finding import Finding, Severity
from scanner.core.registry import Registry
from scanner.core.registry import registry as default_registry
from scanner.core.target import Target


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
    scanners_run: list[str] = field(default_factory=list)

    #: The subset of :attr:`scanners_run` that sends attack-shaped traffic.
    #:
    #: Recorded by the engine from ``cls.requires.active`` rather than derived
    #: here from the name, because ``requires.active`` is the flag the gate itself
    #: reads. Inferring it from a ``-active`` name suffix would be a second,
    #: weaker definition of "intrusive" that a rename could silently falsify —
    #: and this is the one field in the report where being quietly wrong is worse
    #: than being absent.
    active_scanners_run: list[str] = field(default_factory=list)

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
        for cls in selected:
            scanner = cls()
            async for finding in scanner.scan(ctx):
                collected.append(finding)
        return ScanReport(
            findings=dedupe(collected),
            errors=ctx.errors,
            # Recorded from the selection, not from what produced findings: a
            # check that ran and found nothing still sent the requests, and that
            # is exactly the case the disclosure exists for.
            scanners_run=[cls.name for cls in selected],
            active_scanners_run=[cls.name for cls in selected if cls.requires.active],
        )
