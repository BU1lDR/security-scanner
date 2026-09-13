"""The SAST scanner (``sast``): walk local code, match the rule pack (contract §12).

Thin orchestrator over three testable units: :mod:`walk` (discover + read files),
the rule pack (:mod:`rules`), and :mod:`matcher` (text -> redacted findings). It
reads the ``sast.*`` config surface (enabled, exclude_dirs, min_confidence) and
scans each file under fault isolation, so one unreadable or pathological file is
recorded as a scan error and the rest continue (decisions.md D13).

There is no HTTP here — SAST is offline and needs only ``ctx.target.code_path``.
"""

from __future__ import annotations

from scanner.core.finding import Confidence, Finding
from scanner.core.registry import register
from scanner.core.scanner import Requires, Scanner
from scanner.scanners.sast.matcher import scan_text
from scanner.scanners.sast.walk import iter_source_files, read_text_file

_DEFAULT_EXCLUDES = [".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"]
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
        for path in iter_source_files(root, exclude_dirs=excludes):
            text = read_text_file(path)
            if text is None:
                continue
            display = self._display_path(path, root)
            for finding in await ctx.run_check(
                "sast", display, self._scan_file(text, display, min_conf)
            ):
                yield finding

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
