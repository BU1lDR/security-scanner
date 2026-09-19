"""Add markdown hard breaks where the report intends one label per line.

The cover block and each finding's Location / Route / Related-dependency lines
were written one-per-line, but with no trailing two spaces they are a single
paragraph under the markdown spec -- so they rendered as a run-on. This adds the
break to any bold-label line that is immediately followed by another one.

Run with --apply to write; default is a dry run.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPORT = Path(__file__).parent / "sample-report-pygoat.md"


def main() -> int:
    apply = "--apply" in sys.argv
    lines = REPORT.read_text(encoding="utf-8").split("\n")

    in_fence = False
    changed = []
    for i, line in enumerate(lines):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if (line.strip().startswith("**") and nxt.strip().startswith("**")
                and not line.endswith("  ")):
            changed.append((i + 1, line.strip()[:64]))
            lines[i] = line + "  "

    print(f"{'applying' if apply else 'dry run'}: {len(changed)} lines get a hard break")
    for ln, text in changed:
        print(f"  {ln:>4}: {text}")

    if apply:
        REPORT.write_text("\n".join(lines), encoding="utf-8")
        print("written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
