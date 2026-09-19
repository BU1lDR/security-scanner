"""Assert the test count quoted in decisions.md is the count pytest collects.

This exists because that number was wrong three times in a row, and each time the
thing that made it wrong was adding tests — the most routine change there is. A
figure that goes stale every time the project improves is a figure nobody can
maintain by remembering to, so it is checked instead.

Run from the repo root: ``python tools/check_test_count.py``. Exits non-zero with
both numbers and the line to edit. CI runs it; it needs no network and no state
beyond a collection pass.

Deliberately not clever about where the number may live: one pattern, one file.
Other repos quote this count too (the portfolio, the profile README) and CI here
cannot see them — so when this fails, the fix is usually more than one file. The
error message says so.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "decisions.md"

# "... three report formats and 357 tests." Captures the digits only.
QUOTED = re.compile(r"\b(\d+) tests\b")

# pytest's own summary line, e.g. "357 tests collected in 0.31s". "test" is
# singular when there is exactly one, and there is an "errors" variant; only the
# plain success shape is accepted, so a collection error fails loudly rather than
# matching zero and comparing it to something.
COLLECTED = re.compile(r"^(\d+) tests? collected\b", re.MULTILINE)


def collected_count() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    match = COLLECTED.search(proc.stdout)
    if proc.returncode != 0 or match is None:
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:])
        raise SystemExit(
            "could not read a collected-test count from pytest "
            f"(exit {proc.returncode}); see the output above"
        )
    return int(match.group(1))


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    quoted = QUOTED.search(text)
    if quoted is None:
        print(f"no 'N tests' figure found in {DOC.name} — did the wording change?")
        return 1

    actual = collected_count()
    claimed = int(quoted.group(1))
    if claimed == actual:
        print(f"{DOC.name} says {claimed} tests; pytest collects {actual}. Agreed.")
        return 0

    line_no = text[: quoted.start()].count("\n") + 1
    print(
        f"{DOC.name}:{line_no} claims {claimed} tests; pytest collects {actual}.\n"
        f"Update that line. The same figure is quoted outside this repo — the "
        f"portfolio's js/data.js and assets/resume.src.html, and the profile "
        f"README — and CI here cannot check those, so check them by hand."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
