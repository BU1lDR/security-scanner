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

    def exit_code(self, threshold: Severity) -> int:
        """0 = clean, 1 = a finding at or above ``threshold``. (Exit code 2 is
        reserved for engine-level failure and is decided at the CLI, D14.)"""
        if any(f.severity >= threshold for f in self.findings):
            return 1
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
        for cls in self.select(target, active_enabled=active_enabled):
            scanner = cls()
            async for finding in scanner.scan(ctx):
                collected.append(finding)
        return ScanReport(findings=dedupe(collected), errors=ctx.errors)
