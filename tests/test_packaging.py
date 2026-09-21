"""What the distribution has to contain and be called.

The sdist shipped `tests/` and not `tools/`, `docs/` or `.github/`, so the suite it
shipped could not pass: measured on a clean unpack of 1.3.1, 5 failed and 37 errored,
all of it missing files and none of it the scanner. That is a worse failure than
shipping no tests, because it teaches whoever runs them that red means nothing here.

These assertions are on `MANIFEST.in` rather than on a built artifact on purpose. A
test that shells out to `python -m build` needs the `build` package, network access for
the isolated build environment, and half a minute; this reads the one file that decides
the answer, in milliseconds, with no dependency. The build itself is verified by hand
when the manifest changes, and what this guards is the thing that actually rots — a new
test file reaching for a directory nobody remembered to ship (D64).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "MANIFEST.in"
PYPROJECT = ROOT / "pyproject.toml"

#: Where a test file reaches outside `tests/`: either through a `parent.parent` chain
#: or through a module-level `ROOT` built from one. Both spellings are in use.
_REACH = re.compile(r'(?:parent\.parent|\bROOT)\s*/\s*"([^"]+)"')

#: Shipped by setuptools without being named in the manifest.
_IMPLICIT = frozenset({"pyproject.toml", "README.md", "setup.cfg", "src", "tests"})


def _manifest_paths() -> set[str]:
    """Top-level names `MANIFEST.in` ships, by either directive it uses."""
    shipped: set[str] = set()
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "include":
            shipped.update(parts[1:])
        elif parts[0] == "recursive-include" and len(parts) >= 2:
            shipped.add(parts[1])
    return shipped


def _reached_outside_tests() -> set[str]:
    return {
        name
        for path in sorted((ROOT / "tests").glob("*.py"))
        for name in _REACH.findall(path.read_text(encoding="utf-8"))
    }


def test_the_suite_reaches_outside_itself_at_all():
    """The positive control. Everything below is a subset check, and a subset check
    against an empty set is the assertion shape this repo keeps finding in its own
    gates (D43): if the regex stops matching, the real test must not go quiet."""
    reached = _reached_outside_tests()
    assert reached, (
        "found no test reaching outside tests/, so the manifest check below proves "
        f"nothing — the pattern {_REACH.pattern!r} no longer matches this suite"
    )
    assert {"tools", "docs", ".github"} <= reached, (
        "the three known out-of-tree dependencies should still be found: " f"{sorted(reached)}"
    )


def test_every_path_the_suite_needs_is_in_the_sdist():
    """A test file that reads `docs/`, runs a script in `tools/` or inspects
    `.github/` is a test that fails on an sdist unless that directory ships."""
    shipped = _manifest_paths() | _IMPLICIT
    missing = sorted(name for name in _reached_outside_tests() if name not in shipped)
    assert not missing, (
        f"the suite reads {missing} and MANIFEST.in does not ship them, so `pytest` "
        "on an unpacked sdist will fail on missing files rather than on this code"
    )


def test_the_reasoning_record_ships_with_the_code():
    """`tools/check_test_count.py` reads the test count out of `decisions.md`, and the
    README points a reader at it for why any of this is shaped the way it is. A tool
    that ships without the file it reads is a tool that ships broken."""
    assert "decisions.md" in _manifest_paths()


def _project() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def test_the_distribution_is_named_after_the_command_it_installs():
    """It was `security-scanner`, which is a different author's project on PyPI — so
    the name could never have been published and `pip install security-scanner` got
    somebody else's package. Everything else here already said `secscan`: the console
    script, the User-Agent the scanned party sees, the docs. Pinned to the script name
    rather than to the literal, because the invariant is that they agree."""
    project = _project()
    assert list(project["scripts"]) == ["secscan"]
    assert project["name"] == "secscan"


def test_the_license_is_an_spdx_string_not_the_deprecated_table():
    """`license = { text = "MIT" }` builds today with a warning that names the date it
    stops building: 2027-02-18. A build that fails on a calendar date is already
    broken, and a warning printed on every build is a warning nobody reads."""
    project = _project()
    assert isinstance(project["license"], str), (
        "the TOML-table form is deprecated; use an SPDX string plus license-files"
    )
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
