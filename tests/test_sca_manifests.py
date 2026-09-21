import json
import os

from scanner.scanners.sca.manifests import (
    Dependency,
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
