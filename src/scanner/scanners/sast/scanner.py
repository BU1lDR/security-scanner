"""The SAST scanner (``sast``): walk local code, match the rule pack (contract §12).

Thin orchestrator over three testable units: :mod:`walk` (discover + read files),
the rule pack (:mod:`rules`), and :mod:`matcher` (text -> redacted findings). It
reads the ``sast.*`` config surface (enabled, exclude_dirs, min_confidence) and
scans each file under fault isolation, so one file whose *scan* raises is recorded
as a scan error and the rest continue (decisions.md D13).

A file that cannot be *read* never reaches ``ctx.run_check`` — the loop skips it with
``continue`` — so until D67 it contributed nothing to ``report.errors`` and could not
raise the exit code (D54). ``walk`` now says which of its four reasons applied, and
this scanner splits them: a directory that would not list and a file that would not
open are failures, recorded with ``emit_failure`` so the run exits ``3``, because the
answer for what they contained is not "clean" but "unknown". Oversized and binary
files are declined on purpose and go to ``emit_skip``, aggregated, which does not
move the exit code.

An earlier version of this docstring claimed the errors were recorded when they were
not, and that claim reached three other places before it was caught; it then said so
for as long as it stayed true.

There is no HTTP here — SAST is offline and needs only ``ctx.target.code_path``.
"""

from __future__ import annotations

from pathlib import Path

from scanner.core.config import DEFAULT_EXCLUDE_DIRS
from scanner.core.finding import Confidence, Finding
from scanner.core.registry import register
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.sast.matcher import scan_text
from scanner.scanners.sast.walk import (
    INCOMPLETE_KINDS, WalkProblem, iter_source_files, read_text_file,
)

# Imported rather than copied. This was a seven-entry literal and core/config.py's
# default was a five-entry one; because a Config always has the defaults merged,
# the literal here never ran and the two entries only it listed — venv and
# __pycache__ — were not actually excluded from any scan.
_DEFAULT_EXCLUDES = DEFAULT_EXCLUDE_DIRS
#: How each deliberate skip reads in the report. Keyed by the ``WalkProblem`` kinds
#: *not* in ``INCOMPLETE_KINDS``; anything unrecognized falls back to its own slug
#: rather than raising, because a new kind in ``walk`` must not take the scan down
#: on its way to being described.
_DECLINED_REASON = {
    "too-large": "over the 1 MB size limit",
    "binary": "not text",
}
_CONFIDENCE = {
    "tentative": Confidence.TENTATIVE,
    "firm": Confidence.FIRM,
    "confirmed": Confidence.CONFIRMED,
}


@register
class SastScanner(Scanner):
    name = "sast"
    requires = Requires(code=True)

    async def scan(self, ctx):
        if not ctx.target.has_code:
            return
        cfg = ctx.config
        if cfg is not None and not cfg.get("sast.enabled", True):
            return

        excludes = set(cfg.get("sast.exclude_dirs", _DEFAULT_EXCLUDES) if cfg else _DEFAULT_EXCLUDES)
        min_conf = _CONFIDENCE.get(
            str(cfg.get("sast.min_confidence", "tentative")).lower() if cfg else "tentative",
            Confidence.TENTATIVE,
        )

        root = ctx.target.code_path
        problems: list[WalkProblem] = []
        for path in iter_source_files(root, exclude_dirs=excludes, problems=problems):
            text, problem = read_text_file(path)
            if problem is not None:
                problems.append(problem)
            if text is None:
                continue
            display = self._display_path(path, root)
            for finding in await ctx.run_check(
                "sast", display, self._scan_file(text, display, min_conf)
            ):
                yield finding
        # After the walk, because `problems` is a sink the generator fills as it
        # goes: it is only complete once iteration is. The engine drives this
        # generator to exhaustion, so this line is reached on every scan.
        self._report_problems(ctx, problems, root)

    def _report_problems(self, ctx, problems: list[WalkProblem], root) -> None:
        """Route each unread path to the channel that matches what happened to it.

        One error per failure, uncapped, matching what the crawler does with the
        pages it could not fetch: a caller that needs to know the scan was partial
        also needs to know which paths were missing from it, and a count alone
        cannot be acted on. The policy skips are aggregated into one line each
        instead, because the count *is* the whole message there — nobody is going
        to chase down an individual minified bundle, and a ``skipped`` list with one
        entry per vendored asset would bury the skips that matter.
        """
        declined: dict[str, int] = {}
        for problem in problems:
            where = self._display_path(Path(problem.path), root)
            if problem.kind in INCOMPLETE_KINDS:
                ctx.emit_failure("sast", where, f"{problem.kind}: {problem.detail}")
            else:
                declined[problem.kind] = declined.get(problem.kind, 0) + 1
        for kind, count in sorted(declined.items()):
            subject = "1 file was" if count == 1 else f"{count} files were"
            pronoun = "it is" if count == 1 else "they are"
            ctx.emit_skip(
                "sast",
                f"{subject} not read because {pronoun} "
                f"{_DECLINED_REASON.get(kind, kind)}",
                check=kind,
            )

    @staticmethod
    async def _scan_file(text: str, display: str, min_conf: Confidence) -> list[Finding]:
        return scan_text(text, path=display, min_confidence=min_conf)

    @staticmethod
    def _display_path(path, root) -> str:
        """Path relative to the scanned root when possible, else the raw path —
        keeps findings readable without leaking the machine's directory layout."""
        try:
            return str(path.relative_to(root))
        except (ValueError, TypeError):
            return str(path)
