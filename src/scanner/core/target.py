"""What we are scanning, and what we are allowed to touch.

A scan Target may point at a live URL, a local code path, or both. Its Scope is
the safety boundary: the crawler and every active check must refuse to touch a
URL the Scope does not allow.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.core.scope import Scope

__all__ = ["Scope", "Target"]


@dataclass
class Target:
    """A scan target: a URL, a code path, or both, plus its Scope."""

    url: str | None = None
    code_path: str | None = None
    scope: Scope | None = None

    def __post_init__(self) -> None:
        if not self.url and not self.code_path:
            raise ValueError("A Target needs a url, a code_path, or both.")
        if self.scope is None:
            self.scope = Scope.from_url(self.url) if self.url else Scope()

    @property
    def has_web(self) -> bool:
        # Truthiness (not identity) so an empty-string url agrees with the
        # validation and scope-seeding in __post_init__.
        return bool(self.url)

    @property
    def has_code(self) -> bool:
        return bool(self.code_path)
