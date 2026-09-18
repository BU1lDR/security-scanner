"""The SCA scanner: known-vulnerable dependencies via OSV.dev.

It discovers manifests under the target's code path, resolves the pinned
dependencies, asks OSV which are affected, and emits one Finding per
(dependency, vulnerability). Each OSV id becomes part of the rule id
(``sca.vuln.<osv-id>``) so two different vulnerabilities in the *same* package
version stay distinct through fingerprint de-duplication instead of collapsing.

Severity is computed from the advisory's CVSS vector where present, falling back
to the database's qualitative rating, then to HIGH (a known-vulnerable dependency
is inherently notable). A fix is offered only when a fixed version above the
installed one exists; a dependency bump is the one code-adjacent change policy
allows to be marked auto-applicable (decisions.md D12/D18).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from packaging.version import InvalidVersion, Version

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.fix import Fix, FixKind
from scanner.core.location import Location
from scanner.core.registry import register
from scanner.core.rule_id import is_valid
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.sca.coverage import (
    no_manifest_finding,
    unpinned_findings,
    unsupported_manifest_findings,
)
from scanner.scanners.sca.cvss import base_score, score_to_severity
from scanner.scanners.sca.manifests import (
    CoverageGap,
    Dependency,
    discover,
    parse_manifest,
    pyproject_coverage_gap,
)
from scanner.scanners.sca.osv import OsvClient, Vulnerability

_DEFAULT_EXCLUDES = [".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"]
_DB_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def select_fixed_version(
    current: str, fixed_versions: tuple[str, ...], ecosystem: str
) -> str | None:
    """The smallest published fix strictly greater than ``current``, or ``None``.

    ``ecosystem`` is accepted for future per-ecosystem comparison rules; v1 uses
    PEP 440 ordering, which also sorts the ``X.Y.Z`` npm versions we resolve.
    """
    cur = _parse_version(current)
    if cur is None:
        return None
    above = []
    for fv in fixed_versions:
        parsed = _parse_version(fv)
        if parsed is not None and parsed > cur:
            above.append((parsed, fv))
    if not above:
        return None
    return min(above, key=lambda pair: pair[0])[1]


def _rule_id_for(vuln_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", vuln_id.lower()).strip("-")
    rule_id = f"sca.vuln.{slug}" if slug else "sca.vuln.osv"
    return rule_id if is_valid(rule_id) else "sca.vuln.osv"


def _severity(vuln: Vulnerability) -> Severity:
    scores = [s for s in (base_score(v) for v in vuln.cvss_vectors) if s is not None]
    if scores:
        return score_to_severity(max(scores))
    return _DB_SEVERITY.get((vuln.database_severity or "").upper(), Severity.HIGH)


def _identifiers(vuln: Vulnerability) -> set[str]:
    """Every identifier a vuln is known by (its own id plus aliases), normalized."""
    return {vuln.id.upper()} | {a.upper() for a in vuln.aliases}


def _cluster_vulns(vulns: list[Vulnerability]) -> list[list[Vulnerability]]:
    """Group vulns that describe the same real-world flaw.

    OSV returns one record per source database, so a single CVE often arrives as
    a GHSA *and* a PYSEC *and* a CVE record that alias each other. Two records
    belong together when their identifier sets (id + aliases) intersect; we take
    the connected components of that relation via union-find.
    """
    idents = [_identifiers(v) for v in vulns]
    parent = list(range(len(vulns)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(len(vulns)):
        for j in range(i + 1, len(vulns)):
            if idents[i] & idents[j]:
                parent[find(i)] = find(j)

    groups: dict[int, list[Vulnerability]] = {}
    for i, vuln in enumerate(vulns):
        groups.setdefault(find(i), []).append(vuln)
    return list(groups.values())


def _representative(cluster: list[Vulnerability]) -> Vulnerability:
    """The record to name the finding after: prefer a GHSA advisory (richest,
    usually carries a CVSS vector), then any CVE-bearing record, then by id."""
    def rank(v: Vulnerability) -> tuple:
        upper = v.id.upper()
        has_cve = any(a.upper().startswith("CVE-") for a in (v.id, *v.aliases))
        return (0 if upper.startswith("GHSA-") else 1, 0 if has_cve else 1, v.id)

    return min(cluster, key=rank)


@dataclass(frozen=True)
class _Resolved:
    """What one pass over the tree produced, before anything is queried."""

    root: str
    deps: list[Dependency] = field(default_factory=list)
    gaps: list[CoverageGap] = field(default_factory=list)
    supported_count: int = 0


@register
class ScaScanner(Scanner):
    name = "sca"
    requires = Requires(code=True)

    async def scan(self, ctx):
        if not ctx.target.has_code:
            return
        try:
            resolved = self._resolve(ctx)
        except Exception as exc:  # reported, never swallowed
            ctx.emit_error("sca", "discovery", exc)
            return
        if resolved is None:      # switched off in config — an explicit choice
            return
        # Two checks rather than one, because an OSV outage must not also erase
        # the record of which manifests went unread. Those are independent facts
        # and they fail independently.
        for finding in await ctx.run_check("sca", "coverage", self._coverage(resolved)):
            yield finding
        for finding in await ctx.run_check("sca", "osv", self._analyze(ctx, resolved)):
            yield finding

    async def _coverage(self, res: _Resolved) -> list[Finding]:
        """Everything the scan did not look at. Emitted before the OSV results so
        a reader meets the limits of the scan before its conclusions."""
        findings: list[Finding] = []
        if res.supported_count == 0:
            findings.append(no_manifest_finding(res.root))
        findings.extend(unsupported_manifest_findings(res.gaps, res.root))
        findings.extend(unpinned_findings(res.deps, res.root))
        return findings

    async def _analyze(self, ctx, res: _Resolved) -> list[Finding]:
        queryable = [d for d in res.deps if d.version]
        if not queryable:
            return []
        if ctx.http is None:
            # Dependencies were resolved and then abandoned. Returning [] here is
            # indistinguishable from a clean result, which is the one thing a
            # scanner must never do (D42) — so this is loud.
            names = ", ".join(sorted({d.name for d in queryable})[:5])
            raise RuntimeError(
                f"{len(queryable)} pinned dependencies were resolved but no HTTP "
                f"client is available, so none were checked against OSV: {names}"
            )
        vulns_by_dep = await OsvClient(ctx.http).find_vulns(queryable)
        return [
            self._to_finding(dep, cluster)
            for dep, vulns in vulns_by_dep.items()
            for cluster in _cluster_vulns(vulns)
        ]

    def _resolve(self, ctx) -> _Resolved | None:
        """One tree walk, two answers: what can be checked and what cannot.

        Returns ``None`` when SCA is disabled in config. That stays silent because
        an operator switching a scanner off is a recorded decision, not a gap the
        report has to warn them about.
        """
        cfg = ctx.config
        if cfg is not None and not cfg.get("sca.enabled", True):
            return None
        ecosystems = set(
            cfg.get("sca.ecosystems", ["PyPI", "npm"]) if cfg else ["PyPI", "npm"]
        )
        excludes = cfg.get("sca.exclude_dirs", _DEFAULT_EXCLUDES) if cfg else _DEFAULT_EXCLUDES
        root = ctx.target.code_path
        found = discover(root, exclude_dirs=excludes)
        deps: list[Dependency] = []
        gaps: list[CoverageGap] = list(found.gaps)
        for path in found.supported:
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.name == "pyproject.toml":
                gap = pyproject_coverage_gap(str(path), text)
                if gap is not None:
                    gaps.append(gap)
            for dep in parse_manifest(str(path), text):
                if dep.ecosystem in ecosystems:
                    deps.append(dep)
        return _Resolved(root, deps, gaps, len(found.supported))

    def _to_finding(self, dep, cluster: list[Vulnerability]) -> Finding:
        rep = _representative(cluster)
        # The whole cluster is one flaw, so take the worst severity any record
        # rates it and the earliest fix any record publishes.
        severity = max((_severity(v) for v in cluster), default=Severity.HIGH)
        fixed_versions = tuple(
            fv for v in cluster for fv in v.fixed_for(dep.name, dep.ecosystem)
        )
        fixed = select_fixed_version(dep.version, fixed_versions, dep.ecosystem)
        title = (rep.summary.strip() or f"Known vulnerability in {dep.name}")[:120]

        # Every other id/alias in the cluster, in stable order, minus the one we
        # named the finding after.
        other_ids: list[str] = []
        for v in cluster:
            for ident in (v.id, *v.aliases):
                if ident != rep.id and ident not in other_ids:
                    other_ids.append(ident)

        evidence = f"{dep.name} {dep.version} ({dep.ecosystem}) is affected by {rep.id}"
        if other_ids:
            evidence += f" (aka {', '.join(other_ids)})"
        evidence = evidence[:500]  # the caller's own cap; Finding's is a backstop

        if fixed:
            remediation = f"Upgrade {dep.name} to {fixed} or later."
            fix = Fix(
                kind=FixKind.DEPENDENCY_BUMP,
                description=f"Bump {dep.name} from {dep.version} to {fixed}.",
                apply_safe=True,
                details={
                    "ecosystem": dep.ecosystem,
                    "package": dep.name,
                    "from": dep.version,
                    "to": fixed,
                    "manifest": dep.manifest,
                },
            )
        else:
            remediation = (
                f"No fixed version is published for {rep.id}; review the advisory "
                f"and consider replacing or removing {dep.name}."
            )
            fix = None

        references: list[str] = []
        for v in cluster:
            for url in v.references:
                if url not in references:
                    references.append(url)
        references.append(f"https://osv.dev/vulnerability/{rep.id}")
        for ident in other_ids:
            if ident not in references:
                references.append(ident)

        return Finding(
            rule_id=_rule_id_for(rep.id),
            title=title,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            location=Location.for_dependency(
                dep.ecosystem, dep.name, dep.version, path=dep.manifest, line=dep.line
            ),
            evidence=evidence,
            remediation=remediation,
            scanner="sca",
            references=references,
            fix=fix,
        )
