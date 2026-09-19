"""Ask OSV whether the lowest version each dependency floor admits is vulnerable.

A floor like ``cryptography>=42`` is a claim that 42.0.0 is a supported install.
That claim ages badly: the floor does not move, and advisories against old
versions keep being published. cryptography>=42 sat in pyproject.toml until
42.0.0 had fifteen advisories against it, four of them HIGH — and nothing noticed,
because every environment anyone actually built resolved far above it.

This is the same check secscan's own SCA scanner performs on other people's
manifests, pointed at ours. Running it is not optional good citizenship; a
scanner that ships a vulnerable supported-install claim has a credibility problem
its findings cannot survive.

Deliberately NOT run on push. Its answer depends on what OSV published today, so
wiring it into per-commit CI would redden unrelated pull requests on the morning a
new advisory lands — a check that fails for reasons the commit did not cause
teaches people to ignore it. It runs on a schedule and on demand instead, and
tools/check_test_count.py (whose answer depends only on the tree) is the one that
gates commits. Different failure modes, different triggers.

Usage::

    python tools/check_floors.py            # exit 1 if any floor admits a vuln
    python tools/check_floors.py --json      # machine-readable, same exit code

Needs network. On an OSV outage it exits 2 rather than 0 — an unreachable
database is an unknown answer, not a clean one (decisions.md D42 applies to our
own tooling too).
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
OSV_QUERY = "https://api.osv.dev/v1/query"

# "cryptography>=50" -> ("cryptography", "50"). Only >= is meaningful here: a
# floor is what we are asked about. An exact pin (==) has no range to probe and a
# bare name has no floor at all, so both are reported as unprobeable rather than
# quietly skipped.
FLOOR = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*>=\s*([0-9][0-9A-Za-z.!+-]*)")


def lowest_admitted(spec: str) -> tuple[str, str] | None:
    """The package and the lowest concrete version its floor admits.

    ">=50" admits 50.0.0, not 50 — OSV wants a real version string, and PyPI's
    own ordering treats the two as equal, so padding to three components is safe
    and makes the query answerable.
    """
    match = FLOOR.match(spec)
    if match is None:
        return None
    name, floor = match.group(1), match.group(2)
    parts = floor.split(".")
    if len(parts) < 3 and all(p.isdigit() for p in parts):
        floor = ".".join(parts + ["0"] * (3 - len(parts)))
    return name, floor


def query(name: str, version: str) -> list[dict]:
    body = json.dumps(
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    ).encode()
    request = urllib.request.Request(
        OSV_QUERY, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response).get("vulns", [])


def fixed_versions(vuln: dict) -> list[str]:
    """Every version this advisory says it was fixed in, commit hashes dropped."""
    found = {
        event["fixed"]
        for affected in vuln.get("affected", [])
        for rng in affected.get("ranges", [])
        for event in rng.get("events", [])
        if "fixed" in event
    }
    # OSV's GIT ranges carry 40-hex commit ids in the same field as versions.
    return sorted(v for v in found if not re.fullmatch(r"[0-9a-f]{40}", v))


def version_tuple(value: str) -> tuple:
    """Enough of PEP 440 to order release segments. Non-numeric parts sort low,
    so "50.0.0" > "50.0.0rc1" without pulling in `packaging` — this script has to
    run before the project's own dependencies are necessarily installed."""
    return tuple(int(p) if p.isdigit() else -1 for p in value.split("."))


def dedupe(vulns: list[dict]) -> list[dict]:
    """One entry per real-world flaw.

    OSV returns one record per source database, so a single CVE arrives as a GHSA
    *and* a PYSEC record that alias each other, and the first version of this
    script printed cryptography's eight flaws as fifteen. Records belong together
    when their identifier sets intersect.

    The scanner does this properly in scanners/sca/scanner.py (_cluster_vulns,
    union-find over the alias graph, which also merges A-B and B-C into one
    group). This is the cheap version: it only merges against groups already
    seen, which is enough because OSV lists aliases symmetrically. Kept separate
    rather than imported because that function takes Vulnerability objects and
    this script reads raw JSON — and because a dev tool that cannot run until
    the package imports is a dev tool you cannot use to debug the package.
    """
    groups: list[tuple[set[str], dict]] = []
    for vuln in vulns:
        idents = {vuln["id"].upper()} | {a.upper() for a in vuln.get("aliases", [])}
        for known, _ in groups:
            if known & idents:
                known |= idents
                break
        else:
            groups.append((idents, vuln))
    return [vuln for _, vuln in groups]


def clean_floor(name: str, start: str) -> str | None:
    """The lowest version at or above ``start`` that OSV reports nothing against.

    Not "the highest fixed-in among the advisories affecting ``start``", which is
    what this returned at first and which is wrong in a way that matters: querying
    cryptography at 42.0.0 does not surface CVE-2026-69247, because that flaw was
    introduced later than 42 and 42 is genuinely unaffected. So the advice was
    "raise the floor to >=49" and 49 is still vulnerable — advice that leaves you
    exposed while telling you that you are done.

    Each round jumps to the highest fix the current candidate needs and asks
    again. The candidate strictly increases and there are finitely many
    advisories, so this terminates; the cap is a guard against a pathological
    advisory graph, not an expected outcome.
    """
    candidate = start
    for _ in range(12):
        try:
            vulns = dedupe(query(name, candidate))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None
        if not vulns:
            return candidate
        fixes = [f for v in vulns for f in fixed_versions(v)]
        if not fixes:
            return None                      # an unfixed flaw; no floor helps
        nxt = max(fixes, key=version_tuple)
        if version_tuple(nxt) <= version_tuple(candidate):
            return None                      # not making progress
        candidate = nxt
    return None


def declared_floors() -> list[tuple[str, str, str]]:
    """(where, package, lowest admitted version) for every >= floor in the file."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    sources: list[tuple[str, list[str]]] = [
        ("build-system.requires", data.get("build-system", {}).get("requires", [])),
        ("project.dependencies", data.get("project", {}).get("dependencies", [])),
    ]
    for extra, specs in (
        data.get("project", {}).get("optional-dependencies", {}).items()
    ):
        sources.append((f"project.optional-dependencies.{extra}", specs))

    out, unprobeable = [], []
    for where, specs in sources:
        for spec in specs:
            parsed = lowest_admitted(spec)
            if parsed is None:
                unprobeable.append(f"{where}: {spec}")
            else:
                out.append((where, *parsed))
    for spec in unprobeable:
        print(f"  --   no >= floor to probe: {spec}")
    return out


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    floors = declared_floors()
    results, failed = [], 0

    for where, name, version in floors:
        try:
            vulns = dedupe(query(name, version))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"  ??   {name} {version}: OSV unreachable ({exc})")
            return 2

        entry = {
            "where": where,
            "package": name,
            "lowest_admitted": version,
            "vulns": [
                {
                    "id": v["id"],
                    "aliases": [a for a in v.get("aliases", []) if a.startswith("CVE")],
                    "fixed_in": fixed_versions(v),
                }
                for v in vulns
            ],
        }

        if not vulns:
            results.append(entry)
            if not as_json:
                print(f"  ok   {name}>={version} admits nothing vulnerable")
            continue

        failed += 1
        # Probed, not inferred from the advisories above — see clean_floor().
        suggestion = clean_floor(name, version)
        entry["clean_floor"] = suggestion
        results.append(entry)
        if as_json:
            continue

        print(f"  FAIL {name}>={version} ({where}) admits {len(vulns)} advisory(ies):")
        for v in entry["vulns"]:
            names = ", ".join(v["aliases"]) or v["id"]
            print(f"         {names} - fixed in {', '.join(v['fixed_in']) or '(no fix)'}")
        if suggestion:
            print(f"         raise the floor to >={suggestion} (verified clean)")
        else:
            print("         no clean floor found; pin deliberately or drop the dep")

    if as_json:
        print(json.dumps(results, indent=2))
    elif failed:
        print(f"\n  {failed} floor(s) admit a known-vulnerable version.")
    else:
        print(f"\n  all {len(floors)} floor(s) clean.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
