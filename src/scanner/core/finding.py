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
from scanner.core.redaction import scrub
from scanner.core.rule_id import validate as _validate_rule_id

#: Hard ceiling on ``Finding.evidence``, applied by the dataclass itself.
#: 500 is not arbitrary: it is what every call site that *did* truncate already
#: chose, so adopting it as the boundary changes nothing for them and only binds
#: the three passive DAST checks that truncated nowhere.
EVIDENCE_MAX_LEN = 500

#: Truncation is visible on purpose. A silently shortened string reads like
#: complete evidence, which is how someone concludes a scan found less than it did.
_TRUNCATION_MARKER = "... (truncated)"


def _bounded_evidence(evidence: str) -> str:
    """Scrub then truncate — the two halves of the ``evidence`` contract.

    **Why here and not at the call sites.** The contract used to be documented on
    the field and enforced nowhere, so eight call sites each answered it
    independently and gave four different answers. One of them was wrong in a way
    that leaked target data into reports and into ``--ai`` request bodies. Putting
    it in ``__post_init__`` mirrors :class:`~scanner.core.fix.Fix`, which enforces
    its ``apply_safe`` invariant in the dataclass rather than trusting callers, and
    means a check added later cannot reintroduce the same defect by omission.

    **Why it truncates instead of raising.** ``Fix`` raises, correctly: a bad
    ``apply_safe`` means *our* code is wrong. Evidence length is chosen by whatever
    a target sent back, and killing a scan because a server was verbose would turn
    a cosmetic problem into a denial of service against the operator.

    **Why scrub comes first.** :func:`~scanner.core.redaction.redact` is
    length-preserving, so the order does not change the result's size — it changes
    whether a token straddling the cut survives. Truncate first and the token's
    head stays in the report in plaintext, as a fragment that no longer matches any
    shape and so can never be scrubbed afterwards.

    **What this is not.** A net, not a licence. ``scrub`` knows fixed-format token
    families only; it cannot recognise a password, a session id or an email. Call
    sites still owe it a string that was safe to begin with.
    """
    evidence = scrub(evidence)
    if len(evidence) <= EVIDENCE_MAX_LEN:
        return evidence
    return evidence[: EVIDENCE_MAX_LEN - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


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

    ``location`` is structured (URL / file / dependency). ``evidence`` **must
    already be redacted and truncated by the caller** — that obligation is
    unchanged. ``__post_init__`` additionally scrubs recognisable credentials and
    caps the length, but that is a backstop with a deliberately narrow reach and
    is *not* a substitute for the caller's duty: it sees only ``evidence``, while
    ``title``, ``remediation`` and ``location`` are equally exposed (all four are
    written to reports and sent to the AI provider), and it runs once at
    construction, so later mutation bypasses it entirely.
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
        self.evidence = _bounded_evidence(self.evidence)

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
