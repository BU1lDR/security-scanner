"""The shared context handed to every scanner, and the one error record.

There is exactly one context shape and one error shape (contract §10). A scanner
runs each of its sub-checks through :meth:`ScanContext.run_check`, so a single
crashing check becomes a recorded :class:`ScanError` and the scan continues
(decisions.md D13). The HTTP attribute is always ``http``.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.finding import Finding
    from scanner.core.scope import Scope
    from scanner.core.target import Target


@dataclass
class ScanError:
    scanner: str
    check: str
    message: str
    traceback_str: str | None = None


def _format_tb(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


@dataclass
class ScanContext:
    target: "Target"
    scope: "Scope"
    http: object = None          # AsyncHttpClient (wired by the engine)
    config: object = None
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger("scanner")
    )
    errors: list[ScanError] = field(default_factory=list)

    def emit_error(self, scanner: str, check: str, exc: BaseException) -> None:
        self.errors.append(
            ScanError(
                scanner=scanner,
                check=check,
                message=str(exc) or exc.__class__.__name__,
                traceback_str=_format_tb(exc),
            )
        )

    async def run_check(
        self, scanner: str, check: str, coro: Awaitable[list["Finding"]]
    ) -> list["Finding"]:
        """Await ``coro``; on any exception, record a :class:`ScanError` and
        return an empty list so the rest of the scan continues."""
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001 - deliberate fault isolation
            self.emit_error(scanner, check, exc)
            return []
