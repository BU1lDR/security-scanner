"""A thin async client for the OSV.dev vulnerability database (contract §9 egress).

The scanner hands us a list of resolved dependencies; we ask OSV which are
affected. We use the batch endpoint once for every pinned dependency, then fetch
the full record for each distinct vulnerability id. All requests go through the
shared HTTP client, so scope/egress enforcement and rate limiting still apply —
``api.osv.dev`` is on the egress allowlist, never the target scope.

Only dependencies with an *exact* version are queried; an unpinned dependency
has no single version to check.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.scanners.sca.manifests import Dependency

_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/"


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

        ids_by_dep: dict[Dependency, list[str]] = {}
        all_ids: set[str] = set()
        for dep, result in zip(queryable, results):
            ids = [v["id"] for v in ((result or {}).get("vulns", []) or [])]
            if ids:
                ids_by_dep[dep] = ids
                all_ids.update(ids)

        details = {vid: await self._fetch(vid) for vid in sorted(all_ids)}
        return {
            dep: [details[i] for i in ids if i in details]
            for dep, ids in ids_by_dep.items()
        }

    async def _fetch(self, vuln_id: str) -> Vulnerability:
        resp = await self._http.get(_VULN_URL + vuln_id)
        return _parse_vuln(resp.json())
