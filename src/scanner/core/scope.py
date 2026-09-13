"""The target boundary: what the scanner is allowed to touch.

``Scope`` is default-deny. It holds the hosts we may crawl/observe
(``allowed_hosts``), the hosts where intrusive *active* checks are permitted
(``active_allowlist``), and whether the operator has explicitly acknowledged they
are authorized to run active checks (``authorized_ack``).

Active checks are fail-closed: they are permitted for a URL only when all three
hold — the host is in scope, the host is in the active allowlist, and the
authorization has been acknowledged (contract §11, decisions.md D9). This is the
*scope* boundary only; it is distinct from the tool's own infrastructure egress
(see ``scanner.core.egress``), and separate from the ``dast.active.enabled`` flag
the engine also checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Scope:
    """Hosts the scanner may touch, plus the active-check authorization state.

    Host matching is exact — a subdomain is a different host and must be added
    explicitly. This keeps the scanner from wandering off the intended target.
    """

    allowed_hosts: set[str] = field(default_factory=set)
    active_allowlist: set[str] = field(default_factory=set)
    authorized_ack: bool = False

    @classmethod
    def from_url(cls, url: str) -> "Scope":
        """Seed a scope from a target URL. A bare host (``example.com``) is
        accepted; a URL with no resolvable host raises ``ValueError`` rather than
        silently producing an empty deny-all scope that refuses everything."""
        host = urlparse(url).hostname
        if host is None and "://" not in (url or ""):
            # Retry as an authority so a scheme-less bare host parses.
            host = urlparse(f"//{url}").hostname
        if not host:
            raise ValueError(
                f"Cannot determine a host from {url!r}; a scope needs a target host."
            )
        return cls(allowed_hosts={host})

    def allows(self, url: str) -> bool:
        return urlparse(url).hostname in self.allowed_hosts

    def active_allowed(self, url: str) -> bool:
        host = urlparse(url).hostname
        return (
            self.authorized_ack
            and host in self.allowed_hosts
            and host in self.active_allowlist
        )
