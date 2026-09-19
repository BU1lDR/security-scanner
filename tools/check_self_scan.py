"""Scan our own source and require it to come back clean — then require a planted
finding to come back dirty.

Both halves, because either alone is passable by a broken scanner. One that
reports nothing exits 0 on everything; one that reports everything exits 1 on
everything. Only the pair says the exit code carries information.

This replaces a CI step that asserted ``secscan ./src`` exits 1, on the reasoning
that our own source genuinely contains dangerous-looking lines. It does not. All
sixteen SAST findings were the rule pack matching its own rule definitions —
``eval\\s*\\(`` against the string literal ``"Use of eval() on a dynamic value"``
and the docstring explaining what that rule does. The step was pinning the tool's
worst output as its expected output, which is the most expensive kind of green
tick: it made the noise load-bearing, so removing it would have "broken CI".

Usage::

    python tools/check_self_scan.py

Needs the package importable; prefers the installed ``secscan`` console script,
because an entry point can be misdeclared in pyproject.toml while every unit test
still passes. Offline — SAST and the coverage checks need no network, and no URL
is passed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def command() -> list[str]:
    """The installed console script if there is one, else the module."""
    found = shutil.which("secscan")
    return [found] if found else [sys.executable, "-m", "scanner.cli"]


def run(args: list[str]) -> tuple[int, str]:
    env = dict(os.environ)
    # So the module fallback works from a plain checkout, matching pytest's
    # pythonpath setting in pyproject.toml.
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(ROOT / "src"), env.get("PYTHONPATH", "")])
    )
    proc = subprocess.run(
        command() + args, cwd=ROOT, capture_output=True, text=True, env=env
    )
    return proc.returncode, proc.stdout


def our_source_is_clean() -> bool:
    """``./src`` rather than ``.``, and the reason is not convenience.

    Scanning the repo root reports thirteen HIGH secret findings against test
    fixtures, because the secret rules are deliberately exempt from the inert-span
    guard (a hardcoded credential is always in a string literal) and the suite has
    to contain credential-shaped strings to test that they are caught. Those are
    the rules working. ``AKIAIOSFODNN7EXAMPLE`` is AWS's own documented example
    key, and a rule that trusted a dummy-value denylist over the token format
    would be one leaked-key-in-a-fixture away from a false negative.

    Three more come from ``tools/report/sample-report-pygoat.md``, a triage
    document that quotes the strings it is triaging; scanning it re-matches them.

    ``./src`` is the shipped package: the code a user runs, with no fixtures in it.
    That is the thing whose cleanliness is a claim about the tool.
    """
    code, out = run(["./src", "--format", "json"])
    try:
        findings = json.loads(out)["findings"]
    except (json.JSONDecodeError, KeyError):
        print("  FAIL could not parse the JSON report:")
        print(out[-2000:])
        return False

    # Asserted on the findings, not only on the exit code. Exit 0 means "nothing
    # at or above the medium threshold", which a pile of INFO-level noise would
    # also satisfy — and the sixteen this check exists for were HIGH and MEDIUM,
    # so a future regression to a lower severity must not slip through quietly.
    sast = [f for f in findings if f.get("scanner") == "sast"]
    for f in sast:
        loc = f.get("location", {})
        print(f"  FAIL {f['rule_id']} at {loc.get('path')}:{loc.get('line')}")
        print(f"         {f.get('evidence', '')[:160]}")

    if sast:
        print(f"\n  {len(sast)} SAST finding(s) against our own source.")
        print("  Either the code grew a real problem or a rule lost precision.")
        print("  Do not silence this by excluding the file; find out which.")
        return False

    # The one finding we do expect: there is no manifest under src/ (ours is at the
    # repo root), and saying so is D46 working correctly, not a defect.
    expected_info = [f for f in findings if f["rule_id"] == "sca.coverage.no-manifest"]
    print(f"  ok   no SAST findings against ./src"
          f" ({len(findings)} finding(s) total, {len(expected_info)} expected INFO)")

    if code != 0:
        print(f"  FAIL exit was {code}, expected 0")
        return False
    print("  ok   exit 0 on a clean target")
    return True


def a_planted_finding_is_caught() -> bool:
    """The other direction: exit 1 must still be reachable.

    A real call, not a mention — the whole point of the change this guards is that
    those are now different, so the fixture has to be the kind of line that is
    genuinely dangerous.
    """
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "vulnerable.py").write_text(
            "def handler(request):\n    return eval(request.body)\n", encoding="utf-8"
        )
        code, out = run([tmp, "--format", "json"])
        try:
            findings = json.loads(out)["findings"]
        except (json.JSONDecodeError, KeyError):
            print("  FAIL could not parse the JSON report for the planted case")
            return False

        ids = {f["rule_id"] for f in findings}
        if "sast.sink.python-eval" not in ids:
            print(f"  FAIL planted eval() was not reported; got {sorted(ids)}")
            return False
        print("  ok   a planted eval() is still reported")

        if code != 1:
            print(f"  FAIL exit was {code}, expected 1 (D14: a finding at or above"
                  f" the threshold)")
            return False
        print("  ok   exit 1 on a target with a finding")
        return True


def main() -> int:
    # ASCII only. A Windows console defaults to cp1252 and a box-drawing
    # character raises UnicodeEncodeError there, which would make this check fail
    # for a reason that has nothing to do with what it checks.
    print("  -- our own source --")
    clean = our_source_is_clean()
    print("\n  -- a planted finding --")
    caught = a_planted_finding_is_caught()
    ok = clean and caught
    print("\n  " + ("both directions hold." if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
