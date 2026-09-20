"""The floors checker's own behaviour, which nothing used to assert.

tools/check_floors.py is a guard, and the defect it was just fixed for is the one
guards fail at: it answered "all clean" over a pyproject whose cryptography pin was
the exact version its own docstring calls vulnerable. A guard that can report clean
when it did not look is worse than no guard, so the four exit codes it now
distinguishes are asserted here rather than trusted.

Loaded by path, not imported. pyproject sets ``pythonpath = ["src"]``, and that is
deliberate for this file specifically: check_floors.py is stdlib-only so that it
runs before the project's own dependencies are necessarily installed — the whole
point, since what it checks is which versions of those dependencies are admitted.
Making it importable as part of the package would put the cycle back.

Every test stubs ``query``. The suite runs with sockets blocked (pytest-socket), so
a test that asked OSV would not merely be slow, it would fail — and it should:
asking the live database what it thinks today would make these tests go red on
OSV's publishing schedule instead of on this repository's behaviour. That is the
same reason tools/check_floors.py is not wired into per-push CI, and the reason is
worth obeying twice.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "check_floors.py"


@pytest.fixture
def cf():
    """A fresh module per test — the tests reassign PYPROJECT and query."""
    spec = importlib.util.spec_from_file_location("check_floors_under_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pyproject(tmp_path: Path, deps, build=()) -> Path:
    """A minimal pyproject declaring exactly the specs a test cares about."""
    quoted = lambda specs: ", ".join('"{}"'.format(s) for s in specs)  # noqa: E731
    (tmp_path / "pyproject.toml").write_text(
        "[build-system]\nrequires = [{}]\n\n"
        '[project]\nname = "x"\nversion = "0"\ndependencies = [{}]\n'.format(
            quoted(build), quoted(deps)
        ),
        encoding="utf-8",
    )
    return tmp_path / "pyproject.toml"


def _vuln(vid="GHSA-aaaa-bbbb-cccc", aliases=("CVE-2026-00001",), fixed="9.9.9"):
    """One OSV record, shaped the way the script reads them."""
    return {
        "id": vid,
        "aliases": list(aliases),
        "affected": [
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}
        ],
    }


def _clean(name, version):
    return []


def _dirty(name, version):
    return [_vuln()]


# ── parsing: which specs name a lowest admitted version ──────────────────────


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("httpx>=0.27", ("httpx", "0.27.0", ">=")),
        ("cryptography>=50", ("cryptography", "50.0.0", ">=")),
        ("pytest>=9.0.3", ("pytest", "9.0.3", ">=")),
        ("baz[extra]>=2", ("baz", "2.0.0", ">=")),
        # The four below are the regression. A pin used to parse as None, so the one
        # spec shape that names an exact version — the shape you write in order to
        # reproduce a bug — was the one shape never queried.
        ("cryptography==42.0.0", ("cryptography", "42.0.0", "==")),
        ("foo===1.2.3", ("foo", "1.2.3", "===")),
        ("bar~=1.4", ("bar", "1.4.0", "~=")),
        ("Jinja2 == 3.1.2", ("Jinja2", "3.1.2", "==")),
    ],
)
def test_specs_naming_a_lowest_version_are_parsed(cf, spec, expected):
    assert cf.lowest_admitted(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "qux>1.0",  # lowest admitted is whatever PyPI publishes next
        "packaging",  # no version at all
        "pkg @ https://example.invalid/x.whl",
        "!=1.0",  # an exclusion names no floor
        "",
    ],
)
def test_specs_naming_no_lowest_version_are_unprobeable(cf, spec):
    assert cf.lowest_admitted(spec) is None


def test_the_operator_is_reported_not_just_the_version(cf):
    """main() needs it to choose between "raise the floor" and "move the pin"."""
    assert cf.lowest_admitted("cryptography==42.0.0")[2] == "=="
    assert cf.lowest_admitted("cryptography>=42.0.0")[2] == ">="


# ── declared_floors: both halves, because one used to be dropped ─────────────


def test_unprobeable_specs_are_returned_rather_than_printed_and_discarded(cf, tmp_path):
    """They were collected into a local list, printed, and never returned, so main()
    could not see them, the exit code could not reflect them, and the summary line
    counted only the specs that had been read."""
    cf.PYPROJECT = _pyproject(tmp_path, ["httpx>=0.27", "packaging"], build=["setuptools>=83"])
    floors, unprobeable = cf.declared_floors()
    assert [(name, version, op) for _, name, version, op in floors] == [
        ("setuptools", "83.0.0", ">="),
        ("httpx", "0.27.0", ">="),
    ]
    assert unprobeable == ["project.dependencies: packaging"]


def test_every_declared_spec_lands_in_exactly_one_half(cf, tmp_path):
    """The denominator the summary line quotes has to add up to what is declared."""
    declared = ["httpx>=0.27", "packaging", "pkg @ https://example.invalid/x.whl", "bar~=1.4"]
    cf.PYPROJECT = _pyproject(tmp_path, declared, build=["setuptools>=83"])
    floors, unprobeable = cf.declared_floors()
    assert len(floors) + len(unprobeable) == len(declared) + 1


def test_optional_dependencies_are_read_too(cf, tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["httpx>=0.27"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=9.0.3", "ruff"]\n',
        encoding="utf-8",
    )
    cf.PYPROJECT = tmp_path / "pyproject.toml"
    floors, unprobeable = cf.declared_floors()
    assert [name for _, name, _, _ in floors] == ["httpx", "pytest"]
    assert unprobeable == ["project.optional-dependencies.dev: ruff"]


# ── the four exit codes ──────────────────────────────────────────────────────


def test_exit_0_only_when_every_declared_spec_was_probed_and_is_clean(cf, tmp_path, monkeypatch, capsys):
    cf.PYPROJECT = _pyproject(tmp_path, ["httpx>=0.27", "cryptography>=50"])
    monkeypatch.setattr(cf, "query", _clean)
    assert cf.main([]) == 0
    out = capsys.readouterr().out
    assert "all 2 floor(s) clean." in out
    assert "  ok   httpx>=0.27.0 admits nothing vulnerable" in out


def test_exit_1_when_a_floor_admits_a_known_vulnerable_version(cf, tmp_path, monkeypatch, capsys):
    cf.PYPROJECT = _pyproject(tmp_path, ["cryptography>=42.0.0"])
    monkeypatch.setattr(cf, "query", _dirty)
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: "50.0.0")
    assert cf.main([]) == 1
    out = capsys.readouterr().out
    assert "FAIL cryptography>=42.0.0 (project.dependencies) admits 1 advisory(ies)" in out
    assert "CVE-2026-00001 - fixed in 9.9.9" in out


def test_exit_3_when_a_spec_could_not_be_probed_at_all(cf, tmp_path, monkeypatch, capsys):
    """This is the case that used to be exit 0. Nothing queried came back
    vulnerable, and the run still established less than it claimed."""
    cf.PYPROJECT = _pyproject(tmp_path, ["httpx>=0.27", "packaging"])
    monkeypatch.setattr(cf, "query", _clean)
    assert cf.main([]) == 3
    out = capsys.readouterr().out
    assert "no version to probe, so not asked about: project.dependencies: packaging" in out
    assert "not the same" in out
    # The old summary quoted the probed count as if it were the whole set.
    assert "all 1 floor(s) clean." not in out
    assert "1 floor(s) clean; 1 spec(s) never asked about." in out


def test_exit_2_when_osv_is_unreachable(cf, tmp_path, monkeypatch, capsys):
    """An outage is an unknown answer, not a clean one, and not the same unknown as
    a spec that was never askable — D42's distinction, split across 2 and 3."""
    import urllib.error

    def boom(name, version):
        raise urllib.error.URLError("no route to host")

    cf.PYPROJECT = _pyproject(tmp_path, ["httpx>=0.27"])
    monkeypatch.setattr(cf, "query", boom)
    assert cf.main([]) == 2
    assert "OSV unreachable" in capsys.readouterr().out


def test_a_confirmed_finding_outranks_an_unprobeable_spec(cf, tmp_path, monkeypatch):
    """D54's precedence rule. `unprobeable` is ungraded in both directions and a
    named advisory is not, so letting the vague result displace the precise one
    would trade a fact for a doubt."""
    cf.PYPROJECT = _pyproject(tmp_path, ["cryptography>=42.0.0", "packaging"])
    monkeypatch.setattr(cf, "query", _dirty)
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: "50.0.0")
    assert cf.main([]) == 1


def test_the_pin_the_guard_used_to_pass(cf, tmp_path, monkeypatch, capsys):
    """The original defect, end to end: pinning cryptography to the version the
    module docstring names as vulnerable produced ok lines and a zero exit."""
    cf.PYPROJECT = _pyproject(tmp_path, ["httpx>=0.27", "cryptography==42.0.0"])
    monkeypatch.setattr(cf, "query", lambda name, v: _dirty(name, v) if name == "cryptography" else [])
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: "50.0.0")
    assert cf.main([]) == 1
    out = capsys.readouterr().out
    assert "FAIL cryptography==42.0.0" in out
    assert "clean." not in out


# ── the remedy has to be applicable to the spec it is offered for ────────────


def test_a_failing_floor_is_told_to_rise(cf, tmp_path, monkeypatch, capsys):
    cf.PYPROJECT = _pyproject(tmp_path, ["cryptography>=42.0.0"])
    monkeypatch.setattr(cf, "query", _dirty)
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: "50.0.0")
    cf.main([])
    out = capsys.readouterr().out
    assert "raise the floor to >=50.0.0 (verified clean)" in out


def test_a_failing_pin_is_told_to_move_because_it_has_nothing_to_rise_into(cf, tmp_path, monkeypatch, capsys):
    """A pin is its own ceiling. "raise the floor to >=50" against `==42.0.0` reads
    as inapplicable, and advice that reads as inapplicable gets ignored."""
    cf.PYPROJECT = _pyproject(tmp_path, ["cryptography==42.0.0"])
    monkeypatch.setattr(cf, "query", _dirty)
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: "50.0.0")
    cf.main([])
    out = capsys.readouterr().out
    assert "move the pin to ==50.0.0 (verified clean)" in out
    assert "raise the floor" not in out


def test_no_clean_version_says_so_rather_than_suggesting_nothing(cf, tmp_path, monkeypatch, capsys):
    cf.PYPROJECT = _pyproject(tmp_path, ["cryptography>=42.0.0"])
    monkeypatch.setattr(cf, "query", _dirty)
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: None)
    cf.main([])
    assert "no clean floor found" in capsys.readouterr().out


# ── --json carries everything the console does ───────────────────────────────


def test_json_reports_the_unprobeable_specs_and_the_operator(cf, tmp_path, monkeypatch, capsys):
    """Both were console-only, which is most of how they stayed invisible: the
    scheduled workflow uploads the artifact."""
    cf.PYPROJECT = _pyproject(tmp_path, ["httpx>=0.27", "packaging"])
    monkeypatch.setattr(cf, "query", _clean)
    assert cf.main(["--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["unprobeable"] == ["project.dependencies: packaging"]
    assert [(f["package"], f["operator"], f["lowest_admitted"]) for f in payload["floors"]] == [
        ("httpx", ">=", "0.27.0")
    ]


def test_json_carries_the_same_exit_code_as_the_console(cf, tmp_path, monkeypatch, capsys):
    cf.PYPROJECT = _pyproject(tmp_path, ["cryptography==42.0.0"])
    monkeypatch.setattr(cf, "query", _dirty)
    monkeypatch.setattr(cf, "clean_floor", lambda name, start: "50.0.0")
    assert cf.main(["--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["floors"][0]["clean_floor"] == "50.0.0"
    assert payload["floors"][0]["vulns"][0]["aliases"] == ["CVE-2026-00001"]


# ── clean_floor: the suggestion has to be probed, not inferred ───────────────


def test_the_suggested_floor_is_probed_forward_not_read_off_the_advisories(cf, monkeypatch):
    """The first version returned the highest fixed-in among the advisories
    affecting `start`, which is wrong in the direction that matters: a flaw
    introduced *after* `start` does not appear in that query, so the advice was
    "raise to >=49" while 49 was still vulnerable. Advice that leaves you exposed
    while telling you that you are done is worse than no advice.

    Here 42 is hit by one flaw fixed in 49, and 49 is hit by a later flaw fixed in
    50. Reading fixed-in off the first query alone yields 49."""
    answers = {
        "42.0.0": [_vuln("A", ["CVE-2024-1"], fixed="49.0.0")],
        "49.0.0": [_vuln("B", ["CVE-2026-2"], fixed="50.0.0")],
        "50.0.0": [],
    }
    monkeypatch.setattr(cf, "query", lambda name, version: answers[version])
    assert cf.clean_floor("cryptography", "42.0.0") == "50.0.0"


def test_a_clean_start_is_its_own_answer(cf, monkeypatch):
    monkeypatch.setattr(cf, "query", _clean)
    assert cf.clean_floor("httpx", "0.27.0") == "0.27.0"


def test_an_unfixed_flaw_yields_no_suggestion_rather_than_a_guess(cf, monkeypatch):
    """No version helps, so there is no floor to name. None makes main() print
    "pin deliberately or drop the dep" instead of advice that cannot work."""
    monkeypatch.setattr(cf, "query", lambda name, v: [{"id": "A", "affected": []}])
    assert cf.clean_floor("pkg", "1.0.0") is None


def test_an_advisory_fixed_at_or_below_the_candidate_stops_the_walk(cf, monkeypatch):
    """Otherwise the loop cannot make progress and would spin to the cap."""
    monkeypatch.setattr(cf, "query", lambda name, v: [_vuln("A", ["CVE-1"], fixed="1.0.0")])
    assert cf.clean_floor("pkg", "2.0.0") is None


def test_an_outage_mid_walk_yields_no_suggestion(cf, monkeypatch):
    """main() has already reported the FAIL by then; a failed follow-up query must
    not turn into a fabricated floor."""
    import urllib.error

    def boom(name, version):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(cf, "query", boom)
    assert cf.clean_floor("pkg", "1.0.0") is None


def test_the_walk_terminates_on_a_pathological_advisory_graph(cf, monkeypatch):
    """Every candidate is vulnerable and every fix is higher, so there is no clean
    answer to find. The cap is what makes that a return rather than a hang."""
    calls = []

    def ever_upward(name, version):
        calls.append(version)
        major = int(version.split(".")[0])
        return [_vuln("A", ["CVE-1"], fixed="{}.0.0".format(major + 1))]

    monkeypatch.setattr(cf, "query", ever_upward)
    assert cf.clean_floor("pkg", "1.0.0") is None
    assert len(calls) == 12


def test_prerelease_segments_sort_below_the_release(cf):
    """"50.0.0" > "50.0.0rc1" without pulling in `packaging`, which this script
    cannot import: it has to run before the project's dependencies do."""
    assert cf.version_tuple("50.0.0") > cf.version_tuple("50.0.0rc1")
    assert cf.version_tuple("2.0.0") > cf.version_tuple("1.9.9")


# ── dedupe: the count that justifies raising a floor ─────────────────────────


def test_records_that_alias_each_other_count_once(cf):
    """OSV returns one record per source database, so a single CVE arrives as a
    GHSA and a PYSEC record. Reporting both inflates the number the FAIL line uses
    to argue for a floor bump."""
    ghsa = _vuln("GHSA-aaaa-bbbb-cccc", ["CVE-2026-00001"])
    pysec = _vuln("PYSEC-2026-1", ["CVE-2026-00001"])
    other = _vuln("GHSA-dddd-eeee-ffff", ["CVE-2026-00002"])
    assert [v["id"] for v in cf.dedupe([ghsa, pysec, other])] == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
    ]


def test_commit_hashes_are_not_reported_as_fixed_versions(cf):
    """OSV's GIT ranges put 40-hex commit ids in the same field as versions."""
    vuln = {
        "id": "X",
        "affected": [
            {
                "ranges": [
                    {"type": "GIT", "events": [{"fixed": "a" * 40}]},
                    {"type": "ECOSYSTEM", "events": [{"fixed": "3.1.4"}]},
                ]
            }
        ],
    }
    assert cf.fixed_versions(vuln) == ["3.1.4"]
