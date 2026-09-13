"""The tool's own infrastructure egress allowlist (contract §9).

This is deliberately separate from the target ``Scope``. ``Scope`` is default-
deny and covers hosts we are authorized to *scan*. ``Egress`` covers hosts the
tool calls for its own operation — the vulnerability database, package
registries, and the AI API — which we contact for data but never crawl or
attack. The single HTTP choke point allows a request if its host is in Scope OR
in Egress, and refuses everything else.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

DEFAULT_EGRESS_HOSTS: frozenset[str] = frozenset(
    {
        "api.osv.dev",          # SCA: OSV vulnerability lookups
        "pypi.org",             # SCA: PyPI version resolution
        "registry.npmjs.org",   # SCA: npm version resolution
        "api.anthropic.com",    # AI advisor
    }
)


@dataclass(frozen=True)
class Egress:
    hosts: frozenset[str] = DEFAULT_EGRESS_HOSTS

    def allows(self, url: str) -> bool:
        return urlparse(url).hostname in self.hosts
