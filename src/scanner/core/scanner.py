"""The one interface every scanner implements (contract §11).

A scanner declares what it ``requires`` (a live URL, local code, and/or whether
it performs active/intrusive checks) and implements an async ``scan`` generator
that yields :class:`~scanner.core.finding.Finding` objects as it produces them.
The engine treats every scanner identically: it reads ``requires`` to decide
selection, then iterates ``scan``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.finding import Finding
    from scanner.core.target import Target


@dataclass(frozen=True)
class Requires:
    """What a scanner needs in order to run.

    ``url``/``code`` are surface requirements checked against the target.
    ``active`` marks the scanner as intrusive, so the engine applies the
    fail-closed active-check gate (contract §11) before selecting it.
    """

    url: bool = False
    code: bool = False
    active: bool = False


class Scanner(ABC):
    name: str
    requires: Requires

    @classmethod
    def applicable(cls, target: "Target") -> bool:
        """Whether this scanner's surface requirements are met by ``target``.

        This does not evaluate active-check authorization; the engine gates that
        separately using the scope.
        """
        if cls.requires.url and not target.has_web:
            return False
        if cls.requires.code and not target.has_code:
            return False
        return True

    @abstractmethod
    def scan(self, ctx) -> AsyncIterator["Finding"]:
        """Async generator yielding findings. Implementations use ``async def``
        with ``yield`` and report failures via ``ctx`` rather than raising."""
        raise NotImplementedError
