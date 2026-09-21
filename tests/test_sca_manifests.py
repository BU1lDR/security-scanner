import json
import os

from scanner.scanners.sca.manifests import (
    Dependency,
    UnresolvedDeclaration,
    discover,
    discover_manifests,
    parse_manifest,
    parse_package_json,
    parse_package_lock,
    parse_pyproject,
    parse_requirements_txt,
)


# --- requirements.txt ---

def test_requirements_exact_pin():
    deps = parse_requirements_txt("flask==2.0.1\n", "requirements.txt")
    assert deps == [Dependency("PyPI", "flask", "2.0.1", "requirements.txt", 1)]


def test_requirements_normalizes_pypi_name():
    deps = parse_requirements_txt("Django_REST.Framework==3.1\n", "r.txt")
    assert deps[0].name == "django-rest-framework"


def test_requirements_extras_and_markers_are_stripped():
    deps = parse_requirements_txt(
        'requests[security]==2.25.0 ; python_version < "3.8"\n', "r.txt"
    )
    assert deps[0].name == "requests"
    assert deps[0].version == "2.25.0"


def test_requirements_non_exact_version_is_none():
    deps = parse_requirements_txt("urllib3>=1.26\nsix\n", "r.txt")
    assert deps[0].version is None  # a range is not an exact version
    assert deps[1].version is None  # unpinned


def test_requirements_skips_comments_blanks_and_options():
    text = (
        "# a comment\n"
        "\n"
        "-r base.txt\n"
        "-e .\n"
        "--hash=sha256:abc\n"
        "flask==2.0  # inline comment\n"
    )
    deps = parse_requirements_txt(text, "r.txt")
    assert deps == [Dependency("PyPI", "flask", "2.0", "r.txt", 6)]


# ── the lines it skipped, which nothing recorded (D74) ────────────────────────
#
# The test above is the sixth green test found pinning a defect. It asserts what
# came out and never what was left behind, so `-r base.txt` -- a whole second file
# of dependencies -- passing through it silently is indistinguishable from a file
# that declares only flask. Measured on a seven-line requirements.txt whose entries
# were a pin, a `-r`, two URL references, a wheel path, an index option and a range:
# the report named two dependencies and said the file declared two.


def _kinds(unresolved):
    return [(u.kind, u.line) for u in unresolved]


def test_a_referenced_requirements_file_is_recorded_not_dropped():
    unresolved = []
    deps = parse_requirements_txt(
        "flask==2.0\n-r base.txt\n-c constraints.txt\n", "r.txt",
        unresolved=unresolved,
    )
    assert deps == [Dependency("PyPI", "flask", "2.0", "r.txt", 1)]
    assert _kinds(unresolved) == [("requirement-file", 2), ("requirement-file", 3)]
    assert all(u.manifest == "r.txt" and u.ecosystem == "PyPI" for u in unresolved)


def test_pip_configuration_options_are_not_recorded_as_lost_coverage():
    """The split that keeps this from being noise. These four change how pip
    installs and declare no dependency at all, so recording them would report a
    coverage gap on a file that has none."""
    text = (
        "--index-url https://pypi.example.com/simple\n"
        "--find-links ./wheels\n"
        "--hash=sha256:abc\n"
        "--no-binary :all:\n"
        "flask==2.0\n"
    )
    unresolved = []
    deps = parse_requirements_txt(text, "r.txt", unresolved=unresolved)
    assert [d.name for d in deps] == ["flask"]
    assert unresolved == []


def test_an_option_with_its_argument_attached_is_still_recognized():
    """pip accepts ``-rbase.txt``. Matching on the whole token alone would file it
    under "unrecognized", which is a true statement about the wrong thing."""
    unresolved = []
    parse_requirements_txt("-rbase.txt\n-cpins.txt\n-e.\n", "r.txt",
                           unresolved=unresolved)
    assert _kinds(unresolved) == [
        ("requirement-file", 1), ("requirement-file", 2), ("editable-install", 3),
    ]


def test_a_direct_url_or_vcs_reference_is_recorded():
    text = (
        "urllib3 @ https://files.pythonhosted.org/packages/urllib3-1.24.1.tar.gz\n"
        "git+https://github.com/psf/requests@v2.19.1#egg=requests\n"
    )
    unresolved = []
    assert parse_requirements_txt(text, "r.txt", unresolved=unresolved) == []
    assert _kinds(unresolved) == [("direct-reference", 1), ("direct-reference", 2)]


def test_a_local_archive_path_is_recorded_as_such():
    unresolved = []
    parse_requirements_txt("./wheels/foo-1.0-py3-none-any.whl\n", "r.txt",
                           unresolved=unresolved)
    assert _kinds(unresolved) == [("local-artifact", 1)]


def test_a_fully_pinned_file_records_nothing_unresolved():
    """The other direction. A channel that reports a gap in every file reports
    nothing about any of them."""
    unresolved = []
    deps = parse_requirements_txt(
        "flask==2.0\n# comment\n\nrequests>=2.0\n", "r.txt", unresolved=unresolved
    )
    assert len(deps) == 2          # the range is carried through as version=None
    assert unresolved == []


def test_the_sink_is_optional_so_the_default_call_still_works():
    """Every pre-D74 caller passed nothing and must keep working: the sink is a
    report channel, not a control-flow one."""
    assert parse_requirements_txt("-r base.txt\nflask==2.0\n", "r.txt") == [
        Dependency("PyPI", "flask", "2.0", "r.txt", 2)
    ]
    assert parse_pyproject('[project]\ndependencies = ["x @ file:///x"]\n', "p.toml") == []


def test_pyproject_records_unresolved_specs_with_no_line_number():
    """``tomllib`` returns values, not positions, so there is no line to name. The
    record still has to exist -- a PEP 621 table of URL references is the same hole."""
    text = (
        "[project]\n"
        'name = "x"\n'
        'dependencies = ["flask==2.0", "pkg @ https://example.com/pkg.tar.gz"]\n'
        "\n"
        "[project.optional-dependencies]\n"
        'dev = ["./vendor/tool-1.0.whl"]\n'
    )
    unresolved = []
    deps = parse_pyproject(text, "pyproject.toml", unresolved=unresolved)
    assert [d.name for d in deps] == ["flask"]
    assert _kinds(unresolved) == [("direct-reference", None), ("local-artifact", None)]


def test_parse_manifest_forwards_the_sink_for_both_pep508_formats():
    """The dispatcher is the only thing the scanner calls, so a sink it forgets to
    pass is a sink that is never filled."""
    for name, text in (
        ("requirements.txt", "-r base.txt\n"),
        ("requirements-dev.txt", "-r base.txt\n"),
        ("pyproject.toml", '[project]\ndependencies = ["x @ https://e.com/x.whl"]\n'),
    ):
        unresolved = []
        parse_manifest(name, text, unresolved=unresolved)
        assert len(unresolved) == 1, name
        assert unresolved[0].manifest == name


def test_the_npm_formats_deliberately_fill_nothing():
    """Not an omission. ``package.json`` carries an unresolvable spec through as
    ``version=None``, which the unpinned finding already reports, and
    ``package-lock.json`` skips only local workspace entries -- nothing OSV holds an
    advisory for. A second channel here would duplicate one report and invent another.
    """
    unresolved = []
    deps = parse_manifest(
        "package.json", '{"dependencies": {"lodash": "^4.17.0"}}',
        unresolved=unresolved,
    )
    assert [(d.name, d.version) for d in deps] == [("lodash", None)]
    assert unresolved == []

    unresolved = []
    parse_manifest(
        "package-lock.json",
        json.dumps({"packages": {
            "": {"name": "root"},
            "packages/mylib": {"version": "1.0.0"},
            "node_modules/mylib": {"link": True, "resolved": "packages/mylib"},
            "node_modules/lodash": {"version": "4.17.21"},
        }}),
        unresolved=unresolved,
    )
    assert unresolved == []


def test_the_record_carries_no_line_text_only_a_line_number():
    """A requirements line is exactly where a credential turns up, and this record
    exists to be printed in a report. The pointer is the number."""
    unresolved = []
    parse_requirements_txt(
        "-r https://ci:s3cr3t-token@pypi.internal/reqs.txt\n", "r.txt",
        unresolved=unresolved,
    )
    assert _kinds(unresolved) == [("requirement-file", 1)]
    assert not hasattr(unresolved[0], "text")
    assert "s3cr3t-token" not in repr(unresolved[0])
    assert unresolved[0] == UnresolvedDeclaration("PyPI", "r.txt", "requirement-file", 1)


# --- pyproject.toml (PEP 621) ---

def test_pyproject_pep621_exact_pins():
    text = (
        "[project]\n"
        'name = "x"\n'
        'dependencies = ["flask==2.0.1", "requests>=2.0", "six"]\n'
    )
    deps = parse_pyproject(text, "pyproject.toml")
    by_name = {d.name: d for d in deps}
    assert by_name["flask"].version == "2.0.1"
    assert by_name["requests"].version is None
    assert by_name["six"].version is None


# --- package.json ---

def test_package_json_only_exact_versions():
    text = json.dumps(
        {"dependencies": {"lodash": "4.17.21", "react": "^18.0.0"}}
    )
    deps = parse_package_json(text, "package.json")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].ecosystem == "npm"
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["react"].version is None  # a caret range is not exact


# --- package-lock.json (v2/v3 lockfile) ---

def test_package_lock_reads_exact_versions_from_packages():
    text = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/left-pad": {"version": "1.3.0"},
            },
        }
    )
    deps = parse_package_lock(text, "package-lock.json")
    by_name = {d.name: d.version for d in deps}
    assert by_name == {"lodash": "4.17.21", "left-pad": "1.3.0"}
    assert all(d.ecosystem == "npm" for d in deps)


# --- dispatch + discovery ---

def test_parse_manifest_dispatches_on_filename():
    deps = parse_manifest("requirements.txt", "flask==1.0\n")
    assert deps[0].name == "flask"


def test_discover_manifests_walks_tree_and_skips_excluded_dirs(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "package.json").write_text('{"dependencies":{"x":"1.0.0"}}', encoding="utf-8")

    found = sorted(p.name for p in discover_manifests(tmp_path, exclude_dirs=["node_modules"]))
    assert found == ["package.json", "requirements.txt"]


# ── what the walk could not reach (D69) ──

def _refusing_scandir(monkeypatch, forbidden_name):
    """Make ``os.scandir`` refuse one directory by name, the way a filesystem
    would. Monkeypatched rather than chmod'd because no permission model behaves
    the same on POSIX and Windows, and the branch under test is the ``onerror``
    callback, not the OS."""
    real = os.scandir

    def fake(path=".", *args, **kwargs):
        if os.path.basename(str(path).rstrip("\\/")) == forbidden_name:
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", fake)


def test_a_directory_that_will_not_list_is_reported_not_silently_skipped(
    tmp_path, monkeypatch
):
    (tmp_path / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "package.json").write_text('{"dependencies":{"x":"1.0.0"}}', encoding="utf-8")
    _refusing_scandir(monkeypatch, "locked")

    found = discover(tmp_path)

    # The manifest under `locked` is genuinely gone from the result -- that part
    # cannot be fixed. What the fix adds is that the result says so.
    assert [p.name for p in found.supported] == ["requirements.txt"]
    assert [p.kind for p in found.problems] == ["unlistable-dir"]
    assert found.problems[0].path.endswith("locked")
    assert "Permission denied" in found.problems[0].detail


def test_a_readable_tree_reports_no_problems_at_all(tmp_path):
    """The other direction. Without this, a `problems` list that was never
    appended to would satisfy every assertion above it (D43)."""
    (tmp_path / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")

    found = discover(tmp_path)

    assert len(found.supported) == 2
    assert found.problems == []


def test_an_excluded_directory_is_not_a_problem(tmp_path):
    """Pruning is a decision, not a failure: `node_modules` must not raise the
    exit code of every scan that meets one."""
    (tmp_path / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")

    found = discover(tmp_path, exclude_dirs=["node_modules"])

    assert [p.name for p in found.supported] == ["requirements.txt"]
    assert found.problems == []
