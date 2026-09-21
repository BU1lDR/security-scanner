"""The integration contract says "frozen" twelve times. Nothing checked it.

`docs/specs/v1-integration-contract.md` calls itself "the single source of truth for
how the pieces of the scanner fit together" and marks section after section
"(frozen)" — package layout, the two enums and their integer values, the config
namespace. `docs/configuration.md` has been held to the code since D51 by
`test_config.py::test_the_documentation_invents_no_settings`. The contract had
nothing, and D63 found it describing a gating rule the code did not have.

A document that asserts its own frozenness and is verified by nothing is a document
that drifts silently, which is the one failure mode this project keeps closing in its
own scanner. These tests parse the contract's claims out of the document and compare
them to the code, in both directions — the contract must not name a thing that does
not exist, and must not omit a thing that does (D65).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from scanner.core.finding import Confidence, Severity

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "docs" / "specs" / "v1-integration-contract.md"
PYPROJECT = ROOT / "pyproject.toml"

_TEXT = CONTRACT.read_text(encoding="utf-8")

#: A fenced ```python block. The contract states the frozen enums as real source,
#: which is what makes them checkable rather than merely readable.
_PY_BLOCK = re.compile(r"```python\n(.*?)```", re.DOTALL)

#: `NAME = 0` at one indent level inside a class body.
_MEMBER = re.compile(r"^    ([A-Z][A-Z_]*) = (\d+)\s*$", re.MULTILINE)


def _section(number: int) -> str:
    """The text of `## <number>. ...` up to the next `## ` heading."""
    match = re.search(rf"^## {number}\. .*?(?=^## )", _TEXT, re.DOTALL | re.MULTILINE)
    assert match, f"the contract has no section {number}"
    return match.group(0)


def _bolded(section: str, lead: str) -> str | None:
    """The single backticked name in a `<lead> **`name`**` bullet."""
    match = re.search(rf"{lead}\s+\*\*`([^`]+)`\*\*", section)
    return match.group(1) if match else None


def _enum_in_contract(name: str) -> dict[str, int]:
    """The `NAME = int` members the contract declares for one IntEnum."""
    for block in _PY_BLOCK.findall(_TEXT):
        body = re.search(rf"class {name}\(IntEnum\):\n(.*?)(?=\nclass |\Z)", block, re.DOTALL)
        if body:
            return {member: int(value) for member, value in _MEMBER.findall(body.group(1))}
    return {}


def _project() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def test_the_contract_can_still_be_parsed_at_all():
    """The positive control. Every assertion below compares something parsed out of a
    markdown file against the code, and a parser that silently stops matching turns all
    of them green — the vacuous-pass shape this repo has found in its own gates before
    (D43). If the contract is reformatted, this is what says so."""
    assert _PY_BLOCK.findall(_TEXT), (
        f"no ```python blocks found in {CONTRACT.name}; the enum checks below would "
        "compare the code against an empty set and pass"
    )
    assert _enum_in_contract("Severity"), "the contract's Severity block no longer parses"
    assert _enum_in_contract("Confidence"), "the contract's Confidence block no longer parses"
    layout = _section(1)
    assert _bolded(layout, "The installed package is"), "§1's package bullet no longer parses"
    assert re.findall(r"`scanner\.scanners\.([a-z_]+)`", layout), "§1 lists no subpackages"


def test_the_contract_names_the_distribution_you_install():
    """§1 froze every name an integrator touches — the module, the entry point, each
    subpackage — except the one they type to get the tool. That name was wrong for six
    releases: it was `security-scanner`, a different author's project on PyPI, so no
    release under it could ever have been installed (D64). The one name nobody checked
    is the one that was broken."""
    named = _bolded(_section(1), "The distribution on PyPI is")
    assert named, "§1 does not say what the distribution is called"
    assert named == _project()["name"], (
        f"the contract says the distribution is {named!r}, pyproject.toml says "
        f"{_project()['name']!r}"
    )


def test_the_contract_names_the_package_the_code_actually_ships():
    layout = _section(1)
    package = _bolded(layout, "The installed package is")
    assert (ROOT / "src" / package / "__init__.py").is_file(), (
        f"§1 says the installed package is {package!r}, but src/{package}/ is not a package"
    )
    assert tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["tool"]["setuptools"][
        "packages"
    ]["find"]["where"] == ["src"], "§1's `src/` layout claim no longer matches the build config"


def test_the_contract_names_the_entry_point_pyproject_declares():
    """`Console entry point: secscan = scanner.cli:main` is a claim about a file two
    directories away. Parsed from both sides rather than compared to a literal, so the
    invariant under test is that they agree."""
    match = re.search(r"Console entry point: `([^`]+)`", _section(1))
    assert match, "§1's entry-point bullet no longer parses"
    name, _, target = match.group(1).partition(" = ")
    scripts = _project()["scripts"]
    assert scripts == {name: target}, (
        f"the contract declares {name!r} -> {target!r}; pyproject.toml declares {scripts}"
    )


def test_the_contract_lists_every_scanner_subpackage_and_no_others():
    """Both directions. A contract that names a package which does not exist sends an
    integrator to a dead import; one that omits a package which does exist hides a
    whole scanner from anyone reading the document as the source of truth it claims to
    be — and `dast_active`, the tier that sends attack traffic, is exactly the kind of
    thing that must not be undocumented."""
    listed = set(re.findall(r"`scanner\.scanners\.([a-z_]+)`", _section(1)))
    on_disk = {
        path.name
        for path in (ROOT / "src" / "scanner" / "scanners").iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    }
    assert listed == on_disk, (
        f"the contract lists {sorted(listed)}; src/scanner/scanners/ holds {sorted(on_disk)}"
    )


def test_the_frozen_severity_enum_is_the_one_in_the_code():
    """§2 says "the integer values below are also frozen so anything comparing to a
    literal stays correct" — and the exit-code contract, the `--severity-threshold`
    filter and every stored report do compare to these. A renumbering that the document
    did not follow would reinterpret old reports rather than fail."""
    assert _enum_in_contract("Severity") == {m.name: int(m) for m in Severity}


def test_the_frozen_confidence_enum_is_the_one_in_the_code():
    assert _enum_in_contract("Confidence") == {m.name: int(m) for m in Confidence}
