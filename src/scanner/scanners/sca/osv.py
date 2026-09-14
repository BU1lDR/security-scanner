"""A thin async client for the OSV.dev vulnerability database (contract §9 egress).

The scanner hands us a list of resolved dependencies; we ask OSV which are
affected, in two steps:

1. **Screen** every pinned dependency in a single ``/v1/querybatch`` request.
   That endpoint returns only ``id`` + ``modified`` per hit, which is all we
   need to learn *which* packages are affected.
2. **Detail** only those affected packages, one concurrent ``/v1/query`` each.
   Unlike the batch endpoint, ``/v1/query`` returns *full* records, so a package
   carrying forty advisories costs one request instead of forty.

That keeps the cost at ``1 + (affected packages)`` requests. The obvious
alternatives are both worse: fetching each advisory by id costs
``1 + (distinct vulnerabilities)`` — ~180 requests for a handful of outdated
packages, minutes of wall clock at the shared rate limit — while querying every
package individually costs one request per dependency even when nothing is
vulnerable, which punishes large healthy projects.

All requests go through the shared HTTP client, so scope/egress enforcement and
rate limiting still apply — ``api.osv.dev`` is on the egress allowlist, never
the target scope.

Only dependencies with an *exact* version are queried; an unpinned dependency
has no single version to check.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from scanner.scanners.sca.manifests import Dependency

_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True)
class Affected:
    name: str
    ecosystem: str
    fixed_versions: tuple[str, ...]


@dataclass(frozen=True)
class Vulnerability:
    id: str
    summary: str
    details: str
    aliases: tuple[str, ...]
    references: tuple[str, ...]
    cvss_vectors: tuple[str, ...]
    database_severity: str | None
    affected: tuple[Affected, ...]

    def fixed_for(self, name: str, ecosystem: str) -> tuple[str, ...]:
        """Fixed versions declared for a specific package, or ``()`` if none."""
        for a in self.affected:
            if a.name == name and a.ecosystem == ecosystem:
                return a.fixed_versions
        return ()


def _parse_vuln(data: dict) -> Vulnerability:
    affected: list[Affected] = []
    for a in data.get("affected", []) or []:
        pkg = a.get("package", {}) or {}
        fixed = [
            ev["fixed"]
            for rng in (a.get("ranges", []) or [])
            for ev in (rng.get("events", []) or [])
            if "fixed" in ev
        ]
        affected.append(
            Affected(pkg.get("name", ""), pkg.get("ecosystem", ""), tuple(fixed))
        )
    cvss = tuple(
        s.get("score", "")
        for s in (data.get("severity", []) or [])
        if str(s.get("type", "")).startswith("CVSS") and s.get("score")
    )
    return Vulnerability(
        id=data.get("id", ""),
        summary=data.get("summary", "") or "",
        details=data.get("details", "") or "",
        aliases=tuple(data.get("aliases", []) or []),
        references=tuple(
            r.get("url", "")
            for r in (data.get("references", []) or [])
            if r.get("url")
        ),
        cvss_vectors=cvss,
        database_severity=(data.get("database_specific") or {}).get("severity"),
        affected=tuple(affected),
    )


class OsvClient:
    def __init__(self, http) -> None:
        self._http = http

    async def find_vulns(
        self, deps: list[Dependency]
    ) -> dict[Dependency, list[Vulnerability]]:
        queryable = [d for d in deps if d.version]
        if not queryable:
            return {}

        payload = {
            "queries": [
                {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                for d in queryable
            ]
        }
        resp = await self._http.post(_BATCH_URL, json=payload)
        results = resp.json().get("results", []) or []

        # Step 1 told us which packages are affected; we don't keep the ids,
        # because step 2 re-reads them as full records anyway.
        affected = [
            dep
            for dep, result in zip(queryable, results)
            if ((result or {}).get("vulns") or [])
        ]
        if not affected:
            return {}

        # Step 2: full records, one request per affected package, concurrently —
        # the shared client's semaphore and rate limiter still pace them.
        detailed = await asyncio.gather(*(self._query(dep) for dep in affected))
        return {dep: vulns for dep, vulns in zip(affected, detailed) if vulns}

    async def _query(self, dep: Dependency) -> list[Vulnerability]:
        """Full vulnerability records for one pinned dependency."""
        resp = await self._http.post(
            _QUERY_URL,
            json={
                "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                "version": dep.version,
            },
        )
        return [_parse_vuln(v) for v in (resp.json().get("vulns", []) or [])]
