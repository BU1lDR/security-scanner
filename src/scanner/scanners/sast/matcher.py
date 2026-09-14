"""Turn source text into findings by applying the rule pack line by line.

The matcher is pure: text in, list of :class:`~scanner.core.finding.Finding` out,
no I/O. It walks the file once, and for each line tries every rule whose file
extension matches. A hit becomes a FILE-located finding on that line number.

Two invariants matter here:

- **Secrets are redacted at construction** (contract §4). For a ``redact`` rule
  the evidence is built from :func:`~scanner.core.redaction.redact` on the matched
  value and the source line is *never* used. For a non-secret sink the code line
  itself is the evidence — that is what makes a sink finding actionable — but the
  line is passed through :func:`~scanner.core.redaction.scrub` first.

  That scrub is not belt-and-braces, it closes a real hole. Redaction is decided
  per rule, while *every* rule is tried against *every* line, so one line can
  raise two findings at once: a secret rule that masks the credential and a sink
  rule that quotes the line containing it. ``os.system`` and ``shell=True`` lines
  are exactly where an inline curl auth header or database password shows up, so
  the pairing is routine rather than contrived. Scrubbing happens *before*
  truncation on purpose — slicing first would leave the tail of a token in place
  and no longer matching any shape.

  The limit is worth stating plainly: ``scrub`` knows fixed-format token families,
  so ``os.system("mysql -u root -pHunter2")`` still shows that password. A
  shapeless credential in a quoted line is a residual exposure of showing source
  at all, not something this layer can promise away.
- **Precision guards run before a finding is created**: a ``negate`` pattern
  suppresses the line (e.g. a safe loader), and secret rules additionally require
  the value to clear an entropy floor and not look like a placeholder.
"""

from __future__ import annotations

from pathlib import PurePath

from scanner.core.finding import Confidence, Finding
from scanner.core.location import Location
from scanner.core.redaction import scrub
from scanner.scanners.sast.rules import (
    RULES,
    Rule,
    looks_like_placeholder,
    redact,
    shannon_entropy,
)

_DEFAULT_MAX_LINE_LEN = 2000  # skip minified/generated lines: noisy and slow


def scan_text(
    text: str,
    *,
    path: str,
    rules: list[Rule] = RULES,
    min_confidence: Confidence = Confidence.TENTATIVE,
    max_line_len: int = _DEFAULT_MAX_LINE_LEN,
) -> list[Finding]:
    """Apply ``rules`` to ``text`` and return the findings, one per (rule, line).

    ``path`` is the display path recorded on each finding. Rules below
    ``min_confidence`` are skipped entirely.
    """
    suffix = PurePath(path).suffix
    active = [
        r for r in rules
        if r.applies_to(suffix) and r.confidence >= min_confidence
    ]
    if not active:
        return []

    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > max_line_len:
            continue
        for rule in active:
            finding = _match_line(rule, line, path, lineno)
            if finding is not None:
                findings.append(finding)
    return findings


def _match_line(rule: Rule, line: str, path: str, lineno: int) -> Finding | None:
    match = rule.pattern.search(line)
    if match is None:
        return None
    if rule.negate is not None and rule.negate.search(line):
        return None

    value = match.group(rule.value_group) if rule.value_group else match.group(0)

    if rule.redact:
        # Entropy + placeholder guards apply only to the generic heuristic rules
        # (those with an entropy floor). Fixed-format tokens (AWS/GitHub/…) are
        # trusted by their format alone: suppressing one on a coincidental
        # substring would be a false *negative* on a real leaked credential.
        if rule.min_entropy:
            if shannon_entropy(value) < rule.min_entropy:
                return None
            if looks_like_placeholder(value):
                return None
        evidence = f"{rule.title}: {redact(value)} (value redacted, line {lineno})"
    else:
        # scrub before slicing: a token cut in half is still leaked, and the
        # remaining fragment no longer matches any shape (see module docstring).
        evidence = f"{rule.title} at line {lineno}: {scrub(line.strip())[:200]}"

    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        location=Location.for_file(path, line=lineno),
        evidence=evidence,  # Finding caps and scrubs it (EVIDENCE_MAX_LEN)
        remediation=rule.remediation,
        scanner="sast",
        references=list(rule.references),
        fix=None,
    )
