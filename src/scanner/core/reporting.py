"""Rendering a scan report to a human or machine format (contract §6, §16.11).

Findings are grouped by *family* (the first ``rule_id`` segment — ``sca`` /
``dast`` / ``sast``) for human reports. Severity and confidence become
human-readable strings only here; scanners always emit the enum members.

Three formats are supported:

- ``terminal`` — plain text for a console.
- ``json`` — a machine-readable document (stable enum names, fingerprints).
- ``html`` — a self-contained page (all interpolated content is escaped).
"""

from __future__ import annotations

import html
import json as _json
from collections import Counter

from scanner.core.engine import ScanReport
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.rule_id import family

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def render(report: ScanReport, fmt: str = "terminal", *, target=None) -> str:
    if fmt == "terminal":
        return _render_terminal(report, target)
    if fmt == "json":
        return _render_json(report, target)
    if fmt == "html":
        return _render_html(report, target)
    raise ValueError(f"Unknown report format {fmt!r}; use terminal, json, or html.")


# --- shared helpers ---

def _sort_key(f: Finding) -> tuple:
    return (-int(f.severity), -int(f.confidence), f.rule_id)


def _grouped_by_family(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Findings grouped by family, families ordered by their most severe finding."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(family(f.rule_id), []).append(f)
    for items in groups.values():
        items.sort(key=_sort_key)
    return sorted(
        groups.items(),
        key=lambda kv: (-max(int(f.severity) for f in kv[1]), kv[0]),
    )


def _what_ran(report: ScanReport) -> list[str]:
    """Lines disclosing which scanners ran, and whether any of them attacked.

    A report that lists only findings answers "what is wrong with the target". It
    does not answer "what did this tool do to the target", and for the intrusive
    tier that is the question a report may one day have to answer. Placed near the
    top of the terminal output rather than the bottom: the point is that it is seen
    without being looked for.
    """
    if not report.scanners_run and not report.skipped:
        return []          # hand-built report (a fixture, an older caller)
    lines: list[str] = []
    if report.scanners_run:
        ran = f"Ran: {', '.join(report.scanners_run)}"
        if report.requests_sent is not None:
            ran += f" ({report.requests_sent} requests)"
        lines.append(ran)
    if report.sent_active_traffic:
        sent = report.active_requests_sent
        count = f"{sent} " if sent is not None else ""
        lines.append(
            f"ACTIVE CHECKS RAN. This scan sent {count}attack-shaped requests "
            f"({', '.join(report.active_scanners_run)}) to the target."
        )
    # Printed in the same block as what ran, not tucked in with the errors: a tier
    # that was switched off is the most likely reason a report is emptier than the
    # reader expects, and the whole point of this section is that it is seen
    # without being looked for.
    for skip in report.skipped:
        where = f"{skip.scanner}/{skip.check}" if skip.check else skip.scanner
        lines.append(f"Skipped {where}: {skip.reason}")
    return lines


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {sev.name.lower(): counts.get(sev, 0) for sev in _SEVERITY_ORDER}


def _finding_dict(f: Finding) -> dict:
    loc = f.location
    loc_fields = {
        "kind": loc.kind.value,
        "url": loc.url,
        "method": loc.method,
        "param": loc.param,
        "path": loc.path,
        "line": loc.line,
        "column": loc.column,
        "ecosystem": loc.ecosystem,
        "package": loc.package,
        "version": loc.version,
    }
    location = {k: v for k, v in loc_fields.items() if v is not None}
    fix = None
    if f.fix is not None:
        fix = {
            "kind": f.fix.kind.value,
            "description": f.fix.description,
            "apply_safe": f.fix.apply_safe,
            "details": f.fix.details,
        }
    return {
        "rule_id": f.rule_id,
        "family": family(f.rule_id),
        "scanner": f.scanner,
        "title": f.title,
        "severity": f.severity.name,
        "confidence": f.confidence.name,
        "location": location,
        "location_str": str(loc),
        "evidence": f.evidence,
        "remediation": f.remediation,
        "references": list(f.references),
        "fix": fix,
        "fingerprint": f.fingerprint,
    }


# --- terminal ---

def _render_terminal(report: ScanReport, target) -> str:
    lines: list[str] = ["Security scan report"]
    if target is not None and getattr(target, "url", None):
        lines.append(f"Target: {target.url}")
    lines.extend(_what_ran(report))
    lines.append("")

    if not report.findings:
        lines.append("No findings.")
    else:
        for fam, items in _grouped_by_family(report.findings):
            lines.append(f"== {fam.upper()} ({len(items)}) ==")
            for f in items:
                lines.append(
                    f"[{f.severity.name}] {f.rule_id} - {f.title} "
                    f"(confidence: {f.confidence.name})"
                )
                lines.append(f"    where: {f.location}")
                lines.append(f"    evidence: {f.evidence}")
                lines.append(f"    remediation: {f.remediation}")
                if f.references:
                    lines.append(f"    refs: {', '.join(f.references)}")
                if f.fix is not None:
                    # "auto-applicable" invited the reader to go looking for the
                    # flag that applies it. There isn't one: v1 ships no apply
                    # layer at all, and apply_safe is a classification of the
                    # fix, not a statement about what this tool will do for you.
                    # The tag now describes the change itself.
                    tag = "safe to apply as-is" if f.fix.apply_safe else "manual review"
                    lines.append(f"    fix ({tag}): {f.fix.description}")
            lines.append("")

    counts = _severity_counts(report.findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info"))
    lines.append(f"Summary: {summary} ({len(report.findings)} findings)")

    if report.errors:
        lines.append("")
        lines.append(f"Errors ({len(report.errors)}):")
        for e in report.errors:
            lines.append(f"    [{e.scanner}/{e.check}] {e.message}")

    return "\n".join(lines)


# --- json ---

def _render_json(report: ScanReport, target) -> str:
    doc = {
        "target": getattr(target, "url", None) if target is not None else None,
        "summary": {
            **_severity_counts(report.findings),
            "total": len(report.findings),
        },
        "findings": [_finding_dict(f) for f in sorted(report.findings, key=_sort_key)],
        "errors": [
            {"scanner": e.scanner, "check": e.check, "message": e.message}
            for e in report.errors
        ],
    }
    # Omitted entirely when nothing was recorded, rather than emitted as
    # "sent_active_traffic": false. An unrecorded scan is not a passive scan, and
    # a consumer gating a pipeline on this key should get a missing key it has to
    # handle rather than a reassuring default it will not question. The terminal
    # and HTML renderers print nothing in the same case, for the same reason.
    if report.scanners_run or report.skipped:
        doc["scan"] = {
            "scanners_run": list(report.scanners_run),
            "active_scanners_run": list(report.active_scanners_run),
            "sent_active_traffic": report.sent_active_traffic,
            "requests_sent": report.requests_sent,
            "active_requests_sent": report.active_requests_sent,
            "skipped": [
                {"scanner": s.scanner, "check": s.check, "reason": s.reason}
                for s in report.skipped
            ],
        }

    return _json.dumps(doc, indent=2)


# --- html ---

def _render_html(report: ScanReport, target) -> str:
    def esc(value) -> str:
        return html.escape(str(value))

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>Security scan report</title>",
        "</head><body>",
        "<h1>Security scan report</h1>",
    ]
    if target is not None and getattr(target, "url", None):
        parts.append(f"<p>Target: {esc(target.url)}</p>")
    for line in _what_ran(report):
        emphasis = "strong" if line.startswith("ACTIVE") else "span"
        parts.append(f"<p><{emphasis}>{esc(line)}</{emphasis}></p>")

    counts = _severity_counts(report.findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info"))
    parts.append(f"<p>Summary: {esc(summary)} ({len(report.findings)} findings)</p>")

    if not report.findings:
        parts.append("<p>No findings.</p>")
    else:
        for fam, items in _grouped_by_family(report.findings):
            parts.append(f"<h2>{esc(fam.upper())} ({len(items)})</h2><ul>")
            for f in items:
                parts.append(
                    f"<li><strong>[{esc(f.severity.name)}]</strong> "
                    f"{esc(f.rule_id)} — {esc(f.title)} "
                    f"(confidence: {esc(f.confidence.name)})<br>"
                    f"<em>where:</em> {esc(f.location)}<br>"
                    f"<em>evidence:</em> {esc(f.evidence)}<br>"
                    f"<em>remediation:</em> {esc(f.remediation)}</li>"
                )
            parts.append("</ul>")

    if report.errors:
        parts.append(f"<h2>Errors ({len(report.errors)})</h2><ul>")
        for e in report.errors:
            parts.append(f"<li>[{esc(e.scanner)}/{esc(e.check)}] {esc(e.message)}</li>")
        parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts)
