"""Turn a CVSS v3.x base vector into a numeric score and a Severity bucket.

OSV records carry CVSS vector strings, not numbers. We compute the base score
with the official CVSS v3.1 formula (close enough to v3.0 for bucketing) so the
SCA scanner can assign an accurate severity instead of a flat guess. Vectors that
are not CVSS v3.x (e.g. legacy v2) return ``None`` — the caller falls back to the
database's own qualitative severity.

Reference: FIRST CVSS v3.1 Specification, section 7.1 (base metrics).
"""

from __future__ import annotations

import math

from scanner.core.finding import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= value (spec appendix A)."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    if not vector or not vector.startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, val = part.partition(":")
        if val:
            metrics[key] = val
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        av, ac, pr, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], pr_table[metrics["PR"]], _UI[metrics["UI"]]
        c, i, a = _IMPACT[metrics["C"]], _IMPACT[metrics["I"]], _IMPACT[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def score_to_severity(score: float) -> Severity:
    """Map a CVSS base score onto our Severity scale (CVSS qualitative rating)."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
