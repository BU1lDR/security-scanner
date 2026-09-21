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

import ast
import dataclasses
import importlib
import inspect
import pkgutil
import re
import tomllib
from pathlib import Path

import scanner.core
from scanner.core.finding import Confidence, Severity
from scanner.core.location import Location

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "docs" / "specs" / "v1-integration-contract.md"
PYPROJECT = ROOT / "pyproject.toml"

_TEXT = CONTRACT.read_text(encoding="utf-8")

#: A fenced ```python block. The contract states the frozen enums as real source,
#: which is what makes them checkable rather than merely readable.
_PY_BLOCK = re.compile(r"```python\n(.*?)```", re.DOTALL)

#: `NAME = 0` at one indent level inside a class body.
_MEMBER = re.compile(r"^    ([A-Z][A-Z_]*) = (\d+)\s*$", re.MULTILINE)

#: A `@dataclass`-decorated class and its body, up to the next top-level construct.
#: The decorator is required: the contract also declares enums and a Protocol, and
#: those are checked by name and by member elsewhere, not field by field.
_DOC_DATACLASS = re.compile(
    r"^@dataclass(?:\([^)]*\))?\nclass (\w+)[^\n]*:\n(.*?)(?=^@|^class |\Z)",
    re.DOTALL | re.MULTILINE,
)

#: `field: type` at one indent level. Excludes `def` lines, which have no colon
#: immediately after the first identifier.
_DOC_FIELD = re.compile(r"^    (?!def |async def )(\w+)\s*:", re.MULTILINE)

#: `def name(params)` or `async def name(params)` at one indent level, with the
#: `@property` above it if there is one. Whether a name is called or read is part of
#: the contract: `Finding.fingerprint` is a property, and a block that showed it as a
#: method would send an integrator to `TypeError: 'str' object is not callable`.
_DOC_METHOD = re.compile(
    r"^    (@property\n    )?(?:async )?def (\w+)\(([^)]*)\)", re.MULTILINE
)

#: A `- `Location.for_x(a, b=None)`` constructor bullet from §3.
_DOC_CONSTRUCTOR = re.compile(r"^- `Location\.(\w+)\(([^)]*)\)`", re.MULTILINE)

#: An inline `name(params)` claim in the contract's *prose*, outside the fenced
#: blocks every gate above reads. §9 states `fetch_tls`'s signature this way and has
#: now been wrong about this function twice — D45, then D70 — in the same paragraph,
#: which is what makes prose worth parsing rather than trusting.
_DOC_INLINE_CALL = re.compile(r"`([A-Za-z_][\w.]*)\(([^`)]*)\)`")

#: The document with its fenced blocks removed, so the two gates do not overlap.
_PROSE = _PY_BLOCK.sub("", _TEXT)


def _scanner_namespace() -> dict[str, object]:
    """Every top-level name in every importable `scanner.*` module.

    Built by walking the package rather than from a list, so a signature the
    contract states in prose is resolved wherever it actually lives.
    """
    import scanner

    found: dict[str, object] = {}
    for info in pkgutil.walk_packages(scanner.__path__, prefix="scanner."):
        try:
            module = importlib.import_module(info.name)
        except Exception:                       # an optional import, not our concern
            continue
        for key, value in vars(module).items():
            if not key.startswith("_"):
                found.setdefault(key, value)
    return found


def _inline_signature_claims() -> dict[str, tuple[str, object]]:
    """The prose's `name(params)` claims that assert a signature, resolved.

    Two kinds are dropped rather than checked. A claim with empty parentheses
    (`AsyncHttpClient.request()`) asserts nothing about parameters, and one
    containing `...` (`ctx.run_check(...)`, `Fix(kind=..., details={...})`) is
    illustrative by construction. What is left is a real promise about a real
    signature.
    """
    namespace = _scanner_namespace()
    claims: dict[str, tuple[str, object]] = {}
    for dotted, params in _DOC_INLINE_CALL.findall(_PROSE):
        if not params.strip() or "..." in params:
            continue
        head, _, attr = dotted.rpartition(".")
        target = namespace.get(head or dotted)
        if head and target is not None:
            target = getattr(target, attr, None)
        if callable(target):
            claims[dotted] = (params, target)
    return claims


def _params(text: str) -> list[str]:
    """Parameter names from a signature's inside, `self`/`cls` dropped, `*` kept.

    ``*`` is kept because keyword-only is part of the promise: a documented
    ``emit_skip(scanner, reason, check="")`` that is really
    ``emit_skip(scanner, reason, *, check="")`` sends the reader to a
    ``TypeError``. Defaults are kept too, normalized to their source text, so a
    contract that says a parameter is optional has to be right about that.
    """
    out = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk or chunk in {"self", "cls"}:
            continue
        if chunk == "*":
            out.append("*")
            continue
        name, _, default = chunk.partition("=")
        name = name.split(":")[0].strip()
        if not default:
            out.append(name)
            continue
        # Canonicalized through the literal itself rather than compared as text, so
        # that `check=""` and `check=''` are the same promise. A non-literal default
        # keeps its source text and is compared as written.
        try:
            default = repr(ast.literal_eval(default.strip()))
        except (ValueError, SyntaxError):
            default = default.strip()
        out.append(f"{name}={default}")
    return out


def _signature_params(func) -> list[str]:
    """The same list, built from the live function, for comparison."""
    out = []
    seen_kwonly = False
    for param in inspect.signature(func).parameters.values():
        if param.name in {"self", "cls"}:
            continue
        if param.kind is param.KEYWORD_ONLY and not seen_kwonly:
            seen_kwonly = True
            out.append("*")
        if param.default is inspect.Parameter.empty:
            out.append(param.name)
        else:
            out.append(f"{param.name}={param.default!r}")
    return out


def _doc_dataclasses() -> dict[str, tuple[list[str], dict[str, tuple[str, bool]]]]:
    """Every `@dataclass` the contract declares.

    Returns name -> (field names, {method: (params, is_property)}).
    """
    found: dict[str, tuple[list[str], dict[str, tuple[str, bool]]]] = {}
    for block in _PY_BLOCK.findall(_TEXT):
        for name, body in _DOC_DATACLASS.findall(block):
            found[name] = (
                _DOC_FIELD.findall(body),
                {
                    method: (params, bool(prop))
                    for prop, method, params in _DOC_METHOD.findall(body)
                },
            )
    return found


def _code_dataclasses() -> dict[str, type]:
    """Every dataclass defined under `scanner.core`, by name.

    Scoped to `core` because that is the layer this document freezes; a contract
    block for a class outside it fails with a message saying so rather than
    silently matching nothing.
    """
    found: dict[str, type] = {}
    for info in pkgutil.iter_modules(scanner.core.__path__):
        module = importlib.import_module(f"scanner.core.{info.name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and dataclasses.is_dataclass(obj)
                and obj.__module__.startswith("scanner.")
            ):
                assert found.get(obj.__name__, obj) is obj, (
                    f"two different classes are named {obj.__name__}; this lookup is "
                    f"by name and would compare the contract against whichever won"
                )
                found[obj.__name__] = obj
    return found


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
    # The dataclass comparison below is a loop over whatever the parser found: if the
    # fences or the decorators change shape it iterates zero times and certifies the
    # document by not reading it.
    parsed = _doc_dataclasses()
    assert len(parsed) >= 6, f"only {len(parsed)} @dataclass blocks parsed out of the contract"
    assert parsed["ScanContext"][1], "§10's ScanContext block parses no methods"
    assert len(_DOC_CONSTRUCTOR.findall(_TEXT)) == 3, "§3's constructor bullets no longer parse"


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


# ── the frozen dataclasses, field by field (D68) ───────────────────────────────
#
# D65 checked the names §1 freezes and the integer values §2 freezes, and stopped
# there. Six sections further on, §10's ScanContext block listed six of the class's
# seven fields and two of its four methods: `skipped`, `emit_failure` and
# `emit_skip` — the whole second channel, three decisions' worth of design — were
# absent from the section that opens "One context object, one error record". A
# block marked frozen that is missing a field is worse than no block, because it
# reads as complete.

def test_every_dataclass_the_contract_freezes_has_the_fields_the_code_has():
    """Both directions and in order. A contract that names a field which does not
    exist breaks the first integrator who sets it; one that omits a field hides part
    of the type from the document that calls itself the source of truth. Order is
    included because these are constructed positionally in tests and examples."""
    code = _code_dataclasses()
    for name, (fields, _) in _doc_dataclasses().items():
        assert name in code, (
            f"the contract declares a dataclass {name} that is not defined anywhere "
            f"under scanner.core"
        )
        actual = [f.name for f in dataclasses.fields(code[name])]
        assert fields == actual, (
            f"§ for {name}: the contract says {fields}, the code has {actual}"
        )


def test_every_method_the_contract_promises_exists_with_that_signature():
    """The parameter names too, not just the method name. `emit_error(scanner, check,
    exc)` is an instruction someone follows by keyword, and a renamed parameter is a
    `TypeError` at their call site with a document saying they were right."""
    code = _code_dataclasses()
    checked = 0
    for name, (_, methods) in _doc_dataclasses().items():
        for method, (params, documented_as_property) in methods.items():
            # getattr_static: a property must be inspected, not triggered.
            attribute = inspect.getattr_static(code[name], method, None)
            assert attribute is not None, (
                f"the contract says {name}.{method}() exists; the class has no such "
                f"attribute"
            )
            is_property = isinstance(attribute, property)
            assert is_property == documented_as_property, (
                f"{name}.{method} is {'a property' if is_property else 'a method'} in "
                f"the code and documented as "
                f"{'a property' if documented_as_property else 'a method'}; one of the "
                f"two call sites following this document would raise"
            )
            func = attribute.fget if is_property else attribute
            assert _params(params) == _signature_params(func), (
                f"{name}.{method}: the contract documents "
                f"({', '.join(_params(params))}), the code takes "
                f"({', '.join(_signature_params(func))})"
            )
            checked += 1
    assert checked >= 4, f"only {checked} documented methods were compared"


def test_both_of_the_context_channels_are_documented():
    """Named explicitly, because the test above cannot require this: a document may
    freeze fewer methods than a class has, and the two that were missing are exactly
    the two that decide whether an operator is told the scan was incomplete (D58,
    D59, D66, D67). Whether they are documented is not a detail the generic check
    can infer."""
    _, methods = _doc_dataclasses()["ScanContext"]
    assert "emit_failure" in methods, (
        "§10 does not document emit_failure, the channel every reported-not-raised "
        "failure reaches — the crawl's unread pages, the exposed-file probes, the "
        "SAST walk's unlistable directories"
    )
    assert "emit_skip" in methods, "§10 does not document emit_skip"
    assert "ScanSkip" in _doc_dataclasses(), "§10 documents no ScanSkip record"


def test_the_location_constructors_have_the_documented_signatures():
    """§3 gives three constructor signatures in prose, with their defaults. They are
    what every scanner in the repo builds locations with, so a drifted default here
    is a finding pointing at the wrong place rather than an import error."""
    documented = _DOC_CONSTRUCTOR.findall(_TEXT)
    for method, params in documented:
        func = getattr(Location, method, None)
        assert func is not None, f"§3 documents Location.{method}(), which does not exist"
        assert _params(params) == _signature_params(func), (
            f"Location.{method}: §3 says ({', '.join(_params(params))}), the code takes "
            f"({', '.join(_signature_params(func))})"
        )
    assert {m for m, _ in documented} == {
        name
        for name, value in vars(Location).items()
        if isinstance(value, classmethod) and not name.startswith("_")
    }, "§3's constructor list and Location's classmethods disagree"


def test_every_signature_the_prose_states_matches_the_code():
    """§9 states `fetch_tls(url, gate, *, timeout)` in a sentence, not a code block,
    so every structural gate above reads straight past it. That paragraph has been
    false twice: D45 (the gate argument) and D70 (the return contract). Prose in a
    document that calls itself the source of truth is a claim like any other."""
    claims = _inline_signature_claims()
    # Positive control, and named rather than counted: this gate exists for this
    # function, and a regex that stopped matching would otherwise check nothing
    # and pass (D43).
    assert "fetch_tls" in claims, (
        "the prose no longer states fetch_tls's signature, or the parser stopped "
        "finding it -- either way this gate is now vacuous"
    )
    assert len(claims) >= 4, f"only {len(claims)} prose signature claims parsed"

    for dotted, (params, func) in sorted(claims.items()):
        assert _params(params) == _signature_params(func), (
            f"{dotted}: the contract's prose says ({', '.join(_params(params))}), "
            f"the code takes ({', '.join(_signature_params(func))})"
        )
