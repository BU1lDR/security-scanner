"""Ask OSV whether the lowest version each dependency floor admits is vulnerable.

A floor like ``cryptography>=42`` is a claim that 42.0.0 is a supported install.
That claim ages badly: the floor does not move, and advisories against old
versions keep being published. cryptography>=42 sat in pyproject.toml until OSV
had several HIGH advisories against 42.0.0 — and nothing noticed, because every
environment anyone actually built resolved far above it. This docstring does not
say how many, because that is the one number on this page nobody here controls;
the script's job is to ask, and a figure written down beside it would be a second
answer competing with the live one.

This is the same check secscan's own SCA scanner performs on other people's
manifests, pointed at ours. Running it is not optional good citizenship; a
scanner that ships a vulnerable supported-install claim has a credibility problem
its findings cannot survive.

Deliberately NOT run on push. Its answer depends on what OSV published today, so
wiring it into per-commit CI would redden unrelated pull requests on the morning a
new advisory lands — a check that fails for reasons the commit did not cause
teaches people to ignore it. It runs on a schedule and on demand instead, and
tools/check_test_count.py is the one that gates commits. Different failure modes,
different triggers.

That distinction used to be "ours depends on the world, theirs depends only on the
tree", and it no longer is: check_test_count now reads this repository's GitHub
description, which is off the tree. The distinction that actually mattered survives
the change, though, which is why it was allowed. Nobody on this project controls
what OSV publishes, so that check can go red on a morning when every claim in the
commit is true. The description can only disagree with the suite because someone
here left a number wrong — a real defect, in the copy most people read, and the
only copy no diff can show you.

Usage::

    python tools/check_floors.py            # exit 1 if any floor admits a vuln
    python tools/check_floors.py --json      # machine-readable, same exit code

Exit codes, and the third one is the whole point of the most recent change here:

    0   every declared spec was probed and none admits a known-vulnerable version
    1   at least one does
    2   OSV was unreachable, so nothing was established
    3   every spec that *could* be probed came back clean, but at least one could
        not be probed at all

3 exists because 0 used to cover it. Specs this file could not parse were printed
and then dropped before main() saw them: they could not move the exit code, and the
summary line counted only the specs that had been read, so it said "all 6 floor(s)
clean" over a pyproject declaring seven. Pinning cryptography to the exact version
this docstring calls vulnerable was therefore a green run. D42's rule — an
unreachable database is an unknown answer, not a clean one — already covered this
and was already cited here for the outage case; it just was not applied to the
in-tree half. f048ae5 fixed the same shape of bug in ScanReport.exit_code and took
3 for "ran, but do not read this as complete"; this file now uses 3 the same way,
and for the same reason, so an operator reading either does not have to learn two
vocabularies.
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

# "cryptography>=50" -> ("cryptography", "50", ">="). Four operators name a lowest
# admitted version precisely enough to ask OSV about it:
#
#   >=X    X is the lowest install this project calls supported
#   ==X    X is the only one it admits, which makes it the lowest as well
#   ===X   the same, by arbitrary-string equality
#   ~=X.Y  X.Y is the lowest; the implied upper bound does not move the floor
#
# This comment used to read "an exact pin (==) has no range to probe", and a pin
# was therefore treated as unprobeable. That was backwards. A pin is the most
# precisely answerable spec on this page: exactly one version to ask about and no
# inference from a range at all. What a pin has no room for is the *remedy* — you
# cannot raise a floor that is also a ceiling — and that is a different sentence
# from "cannot be checked". The two were conflated, so the one spec shape somebody
# writes in order to reproduce a bug was the one shape this file would not look at.
#
# An exclusive `>X` stays unprobeable and should: the lowest version it admits is
# whatever PyPI publishes next, which is not a fact about this repository.
SPEC = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(>=|===|==|~=)\s*([0-9][0-9A-Za-z.!+-]*)"
)


def lowest_admitted(spec: str) -> tuple[str, str, str] | None:
    """The package, the lowest concrete version its spec admits, and the operator.

    ">=50" admits 50.0.0, not 50 — OSV wants a real version string, and PyPI's
    own ordering treats the two as equal, so padding to three components is safe
    and makes the query answerable.

    None means there is no lowest version to name at all — a bare package name, a
    URL requirement, an exclusive ``>`` bound. That is the caller's problem to
    report rather than to drop; see main().
    """
    match = SPEC.match(spec)
    if match is None:
        return None
    name, operator, floor = match.group(1), match.group(2), match.group(3)
    parts = floor.split(".")
    if len(parts) < 3 and all(p.isdigit() for p in parts):
        floor = ".".join(parts + ["0"] * (3 - len(parts)))
    return name, floor, operator


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
    *and* a PYSEC record that alias each other. Against cryptography 42.0.0 that
    was fifteen records for nine flaws, and the first version of this script
    reported all fifteen — an inflated count is not a harmless cosmetic bug in a
    tool whose output is meant to justify raising a floor. Records belong together
    when their identifier sets intersect.

    Ratio, not counts: fifteen-for-nine was true on the day the floors were
    raised, and how many of either there are now is OSV's business. The numbers
    are here because this paragraph is about a fixed defect rather than about
    cryptography — the live answer is whatever the script prints today.

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


def declared_floors() -> tuple[list[tuple[str, str, str, str]], list[str]]:
    """Every spec with a lowest admitted version, and every spec without one.

    Both halves are returned, because the second one used to be printed here and
    then dropped. It never reached main(), so a spec this file could not parse
    could not affect the exit code, and "all N floor(s) clean" quietly counted only
    the specs it had managed to read. Pinning cryptography to the exact version
    this file's own docstring names as vulnerable produced six ok lines and a
    zero exit. See the usage block for why that is exit 3 now.
    """
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
                name, version, operator = parsed
                out.append((where, name, version, operator))
    return out, unprobeable


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    floors, unprobeable = declared_floors()
    results, failed = [], 0

    for where, name, version, operator in floors:
        label = f"{name}{operator}{version}"
        try:
            vulns = dedupe(query(name, version))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"  ??   {name} {version}: OSV unreachable ({exc})")
            return 2

        entry = {
            "where": where,
            "package": name,
            "operator": operator,
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
                print(f"  ok   {label} admits nothing vulnerable")
            continue

        failed += 1
        # Probed, not inferred from the advisories above — see clean_floor().
        suggestion = clean_floor(name, version)
        entry["clean_floor"] = suggestion
        results.append(entry)
        if as_json:
            continue

        print(f"  FAIL {label} ({where}) admits {len(vulns)} advisory(ies):")
        for v in entry["vulns"]:
            names = ", ".join(v["aliases"]) or v["id"]
            print(f"         {names} - fixed in {', '.join(v['fixed_in']) or '(no fix)'}")
        if suggestion and operator == ">=":
            print(f"         raise the floor to >={suggestion} (verified clean)")
        elif suggestion:
            # A pin is its own ceiling, so there is nothing to raise it into. The
            # advice has to name the other move, or it reads as inapplicable and
            # gets ignored.
            print(f"         move the pin to {operator}{suggestion} (verified clean)")
        else:
            print("         no clean floor found; pin deliberately or drop the dep")

    if not as_json:
        for spec in unprobeable:
            print(f"  ????  no version to probe, so not asked about: {spec}")

    if as_json:
        # A dict rather than the bare list this printed before. The unprobeable
        # specs have to reach the artifact too: they were console-only, which is
        # most of how they stayed invisible.
        print(json.dumps({"floors": results, "unprobeable": unprobeable}, indent=2))
    elif failed:
        print(f"\n  {failed} floor(s) admit a known-vulnerable version.")
    elif unprobeable:
        print(
            f"\n  {len(floors)} floor(s) clean; {len(unprobeable)} spec(s) never asked about.\n"
            "  Nothing that was queried came back vulnerable, which is not the same\n"
            "  as nothing being vulnerable."
        )
    else:
        print(f"\n  all {len(floors)} floor(s) clean.")

    # Precedence follows D54: a verified finding outranks an incomplete run, so a
    # tree with both exits 1. The reasoning there applies unchanged — `unprobeable`
    # is ungraded, a specific confirmed advisory is not, and letting the vague
    # result displace the precise one trades a fact for a doubt.
    if failed:
        return 1
    return 3 if unprobeable else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
