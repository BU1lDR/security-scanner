"""The target boundary: what the scanner is allowed to touch.

``Scope`` is default-deny. It holds the hosts we may crawl/observe
(``allowed_hosts``), the hosts where intrusive *active* checks are permitted
(``active_allowlist``), whether the operator has explicitly acknowledged they are
authorized to run active checks (``authorized_ack``), and whether a host's
subdomains count as in scope (``allow_subdomains``).

Active checks are fail-closed: they are permitted for a URL only when all three
hold — the host is in scope, the host is in the active allowlist, and the
authorization has been acknowledged (contract §11, decisions.md D9). This is the
*scope* boundary only; it is distinct from the tool's own infrastructure egress
(see ``scanner.core.egress``), and separate from the ``dast.active.enabled`` flag
the engine also checks.

Everything here is a host-string comparison, which is why :func:`_canon` exists:
both sides of the comparison have to be spelled the same way before a default-deny
boundary can be trusted to deny the right things (D60).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


def _canon(host: str | None) -> str:
    """One spelling per host, so the two sides of a comparison can meet.

    ``urlparse`` already lowercases the host it parses, but the hosts in
    ``allowed_hosts`` come from a config file a person typed, and there the
    comparison was raw. ``allowed_hosts = ["Example.com"]`` therefore matched
    nothing at all — including the target it was written to describe — and since
    this class is default-deny, the result was a scan that refused every one of its
    own requests over a capital letter.

    The trailing dot is stripped for the same reason from the other direction:
    ``https://example.com./`` is the fully-qualified spelling of the same host and
    resolves identically, so it must not be a way to read a host that was not
    allowed (or, with ``allow_subdomains``, to slip past the suffix test).
    """
    return (host or "").strip().lower().rstrip(".")


@dataclass
class Scope:
    """Hosts the scanner may touch, plus the active-check authorization state.

    Host matching is exact by default — a subdomain is a different host and must be
    added explicitly. ``allow_subdomains`` relaxes that for ``allowed_hosts`` only,
    so ``sub.example.com`` is in scope for a scan of ``example.com``.

    It deliberately does *not* relax ``active_allowlist``. What you may look at and
    what you may send attack-shaped traffic to are different questions, and only the
    second one is irreversible from the target's point of view: widening the first
    finds more pages, widening the second would aim probes at a host nobody named.
    An explicitly listed ``sub.example.com`` still works, because that host *was*
    named.
    """

    allowed_hosts: set[str] = field(default_factory=set)
    active_allowlist: set[str] = field(default_factory=set)
    authorized_ack: bool = False
    allow_subdomains: bool = False

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

    def _matches(self, url: str, hosts: set[str], *, subdomains: bool) -> bool:
        host = _canon(urlparse(url).hostname)
        if not host:
            return False
        listed = {_canon(h) for h in hosts} - {""}
        if host in listed:
            return True
        if not subdomains:
            return False
        # The leading dot is the whole guarantee: without it ``notexample.com``
        # ends with ``example.com`` and a lookalike domain is inside the boundary.
        return any(host.endswith(f".{name}") for name in listed)

    def allows(self, url: str) -> bool:
        return self._matches(url, self.allowed_hosts, subdomains=self.allow_subdomains)

    def active_allowed(self, url: str) -> bool:
        return (
            self.authorized_ack
            and self.allows(url)
            # Never widened, whatever allow_subdomains says. See the class docstring.
            and self._matches(url, self.active_allowlist, subdomains=False)
        )
