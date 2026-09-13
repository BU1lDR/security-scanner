"""The request-authorization decision behind the single HTTP choke point.

This is the safety-critical rule that decides whether an outbound request is
allowed, and if so whether it is *target* traffic (rate-limited against the
target) or *infrastructure* egress (our own data sources). It is deliberately a
pure, dependency-free component so it can be exhaustively tested; the async HTTP
client delegates to it before every request (contract §9).

Decision order:
- An **active** request is allowed only to a host the scope marks
  active-authorized (in scope + in the active allowlist + authorization
  acknowledged). Infrastructure hosts are never active targets.
- A **passive** request is allowed to an egress (infrastructure) host, or to an
  in-scope target host.
- Anything else raises :class:`OutOfScopeError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from scanner.core.egress import Egress
from scanner.core.scope import Scope

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class OutOfScopeError(Exception):
    """Raised when a request targets a host the scanner is not allowed to reach."""


class RequestClass(Enum):
    TARGET = "target"        # traffic to the scan target (per-target rate limit)
    EGRESS = "egress"        # traffic to tool infrastructure (own budget)


@dataclass
class RequestGate:
    scope: Scope
    egress: Egress

    def authorize(self, url: str, active: bool = False) -> RequestClass:
        scheme = (urlparse(url).scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise OutOfScopeError(
                f"Refusing {url!r}: only http/https requests are authorized, not "
                f"{scheme or 'a scheme-less URL'!r}."
            )
        if active:
            # An infrastructure/egress host is never an attack target, even if it
            # was mistakenly placed into scope + the active allowlist.
            if self.scope.active_allowed(url) and not self.egress.allows(url):
                return RequestClass.TARGET
            raise OutOfScopeError(
                f"Active check not authorized for {url!r}: requires an in-scope, "
                "active-allowlisted, non-infrastructure host with authorization "
                "acknowledged."
            )
        if self.egress.allows(url):
            return RequestClass.EGRESS
        if self.scope.allows(url):
            return RequestClass.TARGET
        raise OutOfScopeError(
            f"Request to {url!r} is neither an in-scope target nor an allowed "
            "infrastructure host."
        )
