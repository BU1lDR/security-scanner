"""Findings that describe what the SCA pass could *not* examine.

decisions.md D42 says "we found nothing" and "we could not look" must never
produce the same output. SCA broke that rule in four places at once: an
unrecognized manifest was dropped during the tree walk, a project with no
recognized manifest returned an empty list, a dependency pinned to a range was
skipped before the query, and a Poetry ``pyproject.toml`` parsed cleanly to zero
dependencies. Each produced exactly the output a clean project produces. A fifth
was a layer further in and outlived the other four: a *line* inside a manifest
that was found, read and parsed, which the PEP 508 parser could not turn into a
dependency and dropped (D74).

Everything here is ``INFO`` / ``CONFIRMED``. ``INFO`` because a coverage gap is
not a vulnerability and must not fail anyone's build — the severity threshold
gates ``exit_code`` only, so these appear in the report without turning CI red.
``CONFIRMED`` because the claim is not a guess: we know exactly which file we did
not read.

The remediation text carries the sentence that matters. A reader who sees "no
Composer findings" concludes the Composer dependencies are fine, and the only
thing standing between them and that conclusion is being told, in the finding
itself, that absence of findings here is not evidence of absence of
vulnerabilities.
"""

from __future__ import annotations

import os

from scanner.core.finding import EVIDENCE_MAX_LEN, Confidence, Finding, Severity
from scanner.core.location import Location
from scanner.scanners.sca.manifests import (
    CoverageGap,
    Dependency,
    UnresolvedDeclaration,
)

#: How many file or package names a single finding lists before summarizing. A
#: report is read by a person; forty names is the same as none.
_MAX_LISTED = 6

#: What each :class:`UnresolvedDeclaration` kind says, as a *noun* phrase following
#: "line 4 — ". Noun phrases and not verb phrases so that one entry can describe one
#: line or five without the sentence having to agree with a count: "lines 3, 4 points
#: at a URL" is what a verb phrase gets you here, and carrying a singular and a plural
#: form for each kind is five more strings to keep in step for no gain.
#:
#: Ordered by how much coverage the kind costs, because that is the order a reader
#: should meet them in: a ``-r`` hides a whole second file of dependencies, an
#: unrecognized line hides one.
#:
#: A kind with no entry falls back to its own slug rather than raising — a new slug
#: in :mod:`manifests` must not take the scan down on its way to being described —
#: but shipping a kind without a sentence is not what that fallback is for.
_UNRESOLVED_REASON: dict[str, str] = {
    "requirement-file": (
        "another requirements file, whose own dependencies were not read"
    ),
    "editable-install": (
        "a local project installed in editable mode, whose own dependencies were "
        "not read"
    ),
    "direct-reference": (
        "a URL or version-control checkout, which names no release this scan can "
        "look up"
    ),
    "local-artifact": (
        "a local archive or wheel, which names no release this scan can look up"
    ),
    "unrecognized": "not a requirement this parser could read",
}
#: The order the phrases appear in, worst coverage loss first.
_UNRESOLVED_ORDER = tuple(_UNRESOLVED_REASON)


def _rel(path: str, root: str) -> str:
    """``path`` relative to the scan root, for evidence a human can scan.

    Falls back to the absolute path on Windows when the two are on different
    drives, which ``relpath`` cannot express.
    """
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _listed(items: list[str]) -> str:
    if len(items) <= _MAX_LISTED:
        return ", ".join(items)
    return f"{', '.join(items[:_MAX_LISTED])} and {len(items) - _MAX_LISTED} more"


def _finding(rule_id, title, location, evidence, remediation) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        location=location,
        evidence=evidence[:EVIDENCE_MAX_LEN],
        remediation=remediation,
        scanner="sca",
    )


def unsupported_manifest_findings(
    gaps: list[CoverageGap], root: str
) -> list[Finding]:
    """One finding per (ecosystem, tool), not per file.

    Two findings saying "Composer was not checked" because a project has both a
    ``composer.json`` and a ``composer.lock`` is the report padding itself.
    """
    grouped: dict[tuple[str, str], list[CoverageGap]] = {}
    for gap in gaps:
        grouped.setdefault(gap.group, []).append(gap)

    findings: list[Finding] = []
    for (ecosystem, label), members in sorted(grouped.items()):
        paths = sorted(g.path for g in members)
        files = _listed([_rel(p, root) for p in paths])

        if members[0].ecosystem_checked:
            evidence = (
                f"Found {files}. {ecosystem} packages are checked by this scan, but only "
                f"where they are declared in a requirements.txt or a PEP 621 "
                f"[project.dependencies] table. The {label} declarations in these files "
                f"were not read, so those dependencies were not examined."
            )
            remediation = (
                f"Absence of findings for these files is not evidence that their "
                f"dependencies are free of known vulnerabilities. Export the resolved "
                f"versions to a format this scan reads — for example "
                f"`poetry export -f requirements.txt` — and scan again."
            )
        else:
            evidence = (
                f"Found {files}. This scan does not check the {ecosystem} ecosystem, so "
                f"the dependencies declared there were not examined."
            )
            remediation = (
                f"Absence of findings for these files is not evidence that their "
                f"dependencies are free of known vulnerabilities. Audit the {label} "
                f"dependencies with a {ecosystem}-aware tool before treating this scan "
                f"as complete."
            )

        findings.append(
            _finding(
                "sca.coverage.unsupported-manifest",
                f"{label} dependencies were not examined",
                Location.for_file(paths[0]),
                evidence,
                remediation,
            )
        )
    return findings


def no_manifest_finding(root: str) -> Finding:
    """Nothing to read at all — the case that used to fold into "No findings"."""
    return _finding(
        "sca.coverage.no-manifest",
        "No supported dependency manifest found; SCA did not run",
        Location.for_file(str(root)),
        f"No requirements.txt, pyproject.toml, package.json or package-lock.json was "
        f"found under {root}. No dependency was resolved, so no dependency was checked.",
        "This is not a clean result: the dependency check had nothing to read. If this "
        "project declares its dependencies in a format this scan does not support, audit "
        "them with a tool that does before treating the dependency set as reviewed.",
    )


def unpinned_findings(deps: list[Dependency], root: str) -> list[Finding]:
    """One finding per manifest holding unpinned entries.

    Grouped per file rather than per dependency on purpose: a mid-sized
    ``requirements.txt`` full of ``>=`` constraints would otherwise bury the real
    findings under forty INFO rows.

    Not querying a range is the correct behaviour and is unchanged —
    ``requests>=2.0`` names no single release, so any version we sent to OSV
    would be a guess. What was wrong was doing it silently.

    The evidence says "of the N dependencies *resolved from*" and not "declared in",
    which it used to. The denominator is what the parser produced, and a file of six
    declarations of which four were URLs produced two — so the old wording put the
    parser's own coverage gap in the report as the file's content (D74). The gap
    itself is :func:`unresolved_declaration_findings`.
    """
    by_manifest: dict[str, list[Dependency]] = {}
    for dep in deps:
        by_manifest.setdefault(dep.manifest, []).append(dep)

    findings: list[Finding] = []
    for manifest, group in sorted(by_manifest.items()):
        unpinned = [d for d in group if not d.version]
        if not unpinned:
            continue
        lines = sorted(d.line for d in unpinned if d.line is not None)
        findings.append(
            _finding(
                "sca.coverage.unpinned-dependency",
                f"Unpinned dependencies in {os.path.basename(manifest)} were not checked",
                Location.for_file(manifest, line=lines[0] if lines else None),
                f"{len(unpinned)} of the {len(group)} dependencies resolved from "
                f"{_rel(manifest, root)} have no exact version: "
                f"{_listed(sorted({d.name for d in unpinned}))}. A range does not "
                f"identify a single release, so these were not queried against the "
                f"vulnerability database.",
                "Pin these to exact versions, or commit a lockfile, so they can be "
                "checked. Until then their vulnerability status is unknown rather than "
                "clean.",
            )
        )
    return findings


def _where(lines: list[int]) -> str:
    """``line 4`` / ``lines 4, 9`` / ``an entry`` when there are no line numbers."""
    numbered = sorted(n for n in lines if n is not None)
    if not numbered:
        return "an entry"
    listed = _listed([str(n) for n in numbered])
    return f"line {listed}" if len(numbered) == 1 else f"lines {listed}"


def unresolved_declaration_findings(
    unresolved: list[UnresolvedDeclaration], root: str
) -> list[Finding]:
    """One finding per manifest holding declarations that did not resolve.

    The fifth and last place SCA answered "we could not look" with the output of
    "we looked and there is nothing here", and the one that survived D42 because it
    is a layer below everything D42 touched. The other four are decided about whole
    files, during discovery or immediately after a parse; this one happens inside a
    loop over the lines of a file that was found, opened and parsed without
    complaint, where a ``continue`` reads as "this line declares nothing" rather
    than as "this line declares something we cannot check".

    Grouped per manifest and then per kind, for the reason :func:`unpinned_findings`
    is grouped per manifest: one INFO row per file that a person will read, not one
    per line that a person will scroll past. Line numbers are listed because they
    are the actionable part and the only part safe to print — see
    :class:`UnresolvedDeclaration` on why the line's text is not carried.
    """
    by_manifest: dict[str, list[UnresolvedDeclaration]] = {}
    for entry in unresolved:
        by_manifest.setdefault(entry.manifest, []).append(entry)

    findings: list[Finding] = []
    for manifest, group in sorted(by_manifest.items()):
        by_kind: dict[str, list[int]] = {}
        for entry in group:
            by_kind.setdefault(entry.kind, []).append(entry.line)
        parts = [
            f"{_where(by_kind[kind])} — {_UNRESOLVED_REASON.get(kind, kind)}"
            for kind in (*_UNRESOLVED_ORDER, *sorted(set(by_kind) - set(_UNRESOLVED_ORDER)))
            if kind in by_kind
        ]
        first = sorted(n for n in (e.line for e in group) if n is not None)
        findings.append(
            _finding(
                "sca.coverage.unresolved-declaration",
                f"Declarations in {os.path.basename(manifest)} were not resolved "
                f"and not checked",
                Location.for_file(manifest, line=first[0] if first else None),
                f"{len(group)} declaration(s) in {_rel(manifest, root)} did not "
                f"resolve to a package and a version, so none of them were queried "
                f"against the vulnerability database: {'; '.join(parts)}.",
                "Absence of findings for these is not evidence that the packages "
                "behind them are free of known vulnerabilities. Declare them as "
                "`name==version`, or pin them in a lockfile. A file pulled in with "
                "`-r` is scanned only when its own name matches `requirements*.txt`.",
            )
        )
    return findings
