"""The gates in tools/ are actually wired into a workflow, both directions.

Every other check in this repository asserts something about the scanner. This one
asserts something about the checks: that each ``tools/check_*.py`` is named by a
``run:`` line in a workflow, and that every tool a ``run:`` line names still
exists. Nothing inside a gate can catch its own absence -- delete the CI step for
tools/check_active_rehearsal.py and the whole suite stays green while the thing it
gates stops being gated (decisions.md D57). The reverse direction is the one that
bites on a rename: the tool moves, CI keeps calling the old path, and the step
fails with "No such file or directory" on a push nobody connects to the rename.

Both workflow files are scanned, not just ci.yml. tools/check_floors.py is gated
by .github/workflows/dependency-floors.yml, on a timer rather than per push, and
for a reason that entry records; scanning ci.yml alone would report it as ungated
while it is gated, which is a false alarm about the one tool whose placement was
deliberate.

Only ``run:`` scalars count. tools/check_floors.py also appears in that workflow's
``paths:`` filter and both workflows discuss tools in prose, so a search of the
whole file text would let a mention stand in for an invocation: delete the
``run:`` line, keep the comment, and the test would still pass.

Text, not YAML: no PyYAML dependency, no sockets, no subprocess, so this runs
under the ``--disable-socket`` leg unchanged.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = ROOT / ".github" / "workflows"

#: Every tool named the way CI names it, from inside a ``run:`` scalar.
TOOL_PATH = re.compile(r"tools/(check_\w+\.py)")

#: ``run: cmd`` or ``run: |``, with or without the ``- `` of a step's first key.
RUN_KEY = re.compile(r"(?P<indent> *)(?:- +)?run:(?P<inline>.*)$")

_BLOCK_SCALARS = {"|", "|-", "|+", ">", ">-", ">+"}


def _run_lines(workflow: Path) -> list[str]:
    """The shell lines a workflow runs: inline ``run:`` values plus block bodies."""
    lines: list[str] = []
    block_indent: int | None = None
    for line in workflow.read_text(encoding="utf-8").splitlines():
        if block_indent is not None:
            if not line.strip():
                continue
            if len(line) - len(line.lstrip()) > block_indent:
                lines.append(line.strip())
                continue
            block_indent = None  # dedented out of the block; fall through
        match = RUN_KEY.match(line)
        if match is None:
            continue
        inline = match.group("inline").strip()
        if inline in _BLOCK_SCALARS:
            block_indent = len(match.group("indent"))
        elif inline:
            lines.append(inline)
    return lines


def _gated_by() -> dict[str, set[str]]:
    """Tool filename -> the workflow files whose ``run:`` lines invoke it."""
    gated: dict[str, set[str]] = {}
    for workflow in _workflows():
        for line in _run_lines(workflow):
            for name in TOOL_PATH.findall(line):
                gated.setdefault(name, set()).add(workflow.name)
    return gated


def _workflows() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yml"))


def _scanned() -> str:
    return ", ".join(w.name for w in _workflows())


def test_every_check_tool_has_a_ci_step():
    tools = {p.name for p in (ROOT / "tools").glob("check_*.py")}
    # Non-vacuity: if tools/ moves, an empty set satisfies every assertion below.
    assert tools, "found no tools/check_*.py at all, so this test proved nothing"
    assert _workflows(), "found no .github/workflows/*.yml, so nothing was scanned"

    ungated = sorted(tools - set(_gated_by()))
    assert not ungated, (
        "no run: line in any of [{}] invokes {} -- a gate nothing runs is not a "
        "gate. Add a step, or if it is deliberately not gated per push, say where "
        "it runs instead (check_floors.py runs from dependency-floors.yml, which "
        "is why both workflow files are scanned here).".format(_scanned(), ungated)
    )


def test_every_ci_run_line_names_a_tool_that_exists():
    gated = _gated_by()
    # Non-vacuity: a workflow whose run: lines stopped parsing would pass silently.
    assert gated, (
        "no run: line in [{}] names a tools/check_*.py, which means either every "
        "gate was deleted or this test stopped reading the workflows".format(_scanned())
    )

    missing = sorted(
        "{} (run by {})".format(name, ", ".join(sorted(where)))
        for name, where in gated.items()
        if not (ROOT / "tools" / name).is_file()
    )
    assert not missing, (
        "a run: line names a tool that is not on disk: {} -- the step will fail on "
        "the next push with a file-not-found error. Workflow files scanned: "
        "[{}].".format(missing, _scanned())
    )
