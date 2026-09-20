"""The shared context handed to every scanner, and the records it collects.

There is exactly one context shape and one error shape (contract §10). A scanner
runs each of its sub-checks through :meth:`ScanContext.run_check`, so a single
crashing check becomes a recorded :class:`ScanError` and the scan continues
(decisions.md D13). The HTTP attribute is always ``http``.

Alongside errors there is a second, quieter channel: :class:`ScanSkip`, for work
that was selected and then declined — a scanner switched off in the config file, a
host in scope but not in the active allowlist. Those are not failures and must not
move the exit code, but they are also not nothing, and before this channel existed
they were indistinguishable from work that ran and found the target clean (D58).
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


@dataclass
class ScanSkip:
    """Work that was selected and then declined, with the reason it was declined.

    Deliberately not a :class:`ScanError`. An error means the scan tried and
    something broke; a skip means it never tried, because it was told not to.
    Folding the two together would push the exit code to 3 on every run that
    switches a tier off in a config file, which trains people to ignore 3 — and
    exit 3 is the signal that the report is not a complete answer.

    ``check`` is empty when the whole scanner declined, and names the sub-check
    otherwise. That distinction is load-bearing: the engine keeps a scanner out of
    ``scanners_run`` only for a whole-scanner skip, because ``dast`` with its TLS
    check disabled did still run.
    """

    scanner: str
    reason: str
    check: str = ""


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
    skipped: list[ScanSkip] = field(default_factory=list)

    def emit_error(self, scanner: str, check: str, exc: BaseException) -> None:
        self.errors.append(
            ScanError(
                scanner=scanner,
                check=check,
                message=str(exc) or exc.__class__.__name__,
                traceback_str=_format_tb(exc),
            )
        )

    def emit_failure(self, scanner: str, check: str, message: str) -> None:
        """Record a failure that was never raised here as an exception.

        Some failures are reported rather than thrown: a crawl hands back the list
        of pages it could not read, having deliberately kept walking past each one.
        Those need the same channel as a crash — an incomplete scan is incomplete
        however politely it was handled — but there is no live traceback to attach,
        and inventing one would put this function's own stack in the report instead
        of the failure's.
        """
        self.errors.append(ScanError(scanner=scanner, check=check, message=message))

    def emit_skip(self, scanner: str, reason: str, *, check: str = "") -> None:
        """Record that ``scanner`` (or one of its checks) declined to run, and why."""
        self.skipped.append(ScanSkip(scanner=scanner, reason=reason, check=check))

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
