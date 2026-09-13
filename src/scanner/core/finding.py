"""The normalized Finding model shared by every scanner.

Every scanner, whatever it inspects, emits results in this one shape so that the
engine, reporting, and AI advisor only ever deal with a single format. See
``docs/specs/v1-integration-contract.md`` §4 for the frozen contract.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from urllib.parse import parse_qsl, urlencode, urlsplit

from scanner.core.fix import Fix
from scanner.core.location import Location, LocationKind
from scanner.core.rule_id import validate as _validate_rule_id


class Severity(IntEnum):
    """How serious a finding is.

    Ordered so findings can be compared against a threshold, e.g.
    ``finding.severity >= Severity.HIGH``.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(IntEnum):
    """How sure we are that a finding is real.

    Ordered so findings can be filtered by a minimum confidence.
    """

    TENTATIVE = 0
    FIRM = 1
    CONFIRMED = 2


def _normalize_url(url: str | None) -> str:
    """Canonical form for fingerprinting: scheme + host + path, query keys
    sorted, fragment dropped (contract §8).

    The identity keys on the *host*, so it is built from ``parts.hostname``
    (lowercased, with any port and userinfo dropped) rather than the raw netloc.
    Two URLs that differ only in host case, a redundant default port, userinfo,
    query order, or a fragment normalize to the same string."""
    if not url:
        return ""
    parts = urlsplit(url)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    host = (parts.hostname or "").lower()
    base = f"{parts.scheme}://{host}{parts.path}"
    return f"{base}?{query}" if query else base


@dataclass
class Finding:
    """A single security issue discovered by a scanner.

    ``location`` is structured (URL / file / dependency). ``evidence`` is a
    human-readable string that must already be redacted and truncated at
    construction — raw secrets or cookie values never reach a Finding.
    ``references`` collects external identifiers (CWE/CVE/OWASP/URLs).
    ``scanner`` is the id of the emitting scanner. ``fix`` is an optional
    structured remediation; it stays ``None`` when there is no machine-usable fix.
    """

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: str
    remediation: str
    scanner: str
    references: list[str] = field(default_factory=list)
    fix: Fix | None = None

    def __post_init__(self) -> None:
        # Enforce the rule_id grammar at emit/construction time (contract §5),
        # matching the invariant checks the sibling Fix and Target dataclasses do.
        _validate_rule_id(self.rule_id)

    @property
    def fingerprint(self) -> str:
        """Stable identity for cross-scanner de-duplication (contract §8)."""
        loc = self.location
        if loc.kind is LocationKind.URL:
            ident = "|".join(
                (_normalize_url(loc.url), loc.method or "", loc.param or "")
            )
        elif loc.kind is LocationKind.FILE:
            ident = "|".join((loc.path or "", str(loc.line) if loc.line is not None else ""))
        else:  # DEPENDENCY
            ident = "|".join((loc.ecosystem or "", loc.package or "", loc.version or ""))
        key = f"{self.rule_id}||{ident}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()
