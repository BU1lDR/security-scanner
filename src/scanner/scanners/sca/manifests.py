"""Finding and parsing dependency manifests into a normalized dependency list.

SCA is only meaningful for versions we actually know are present, so the parsers
extract a version *only when it is exact* — a pin (``==2.0.1``, an npm ``1.2.3``,
a lockfile entry). Ranges and unpinned entries yield ``version=None`` and are
carried through so the scanner can report "unpinned, cannot check" rather than
guessing. Lockfiles (``package-lock.json``) are where exact versions are richest.

Supported in v1: ``requirements.txt`` / ``pyproject.toml`` (PyPI) and
``package.json`` / ``package-lock.json`` (npm). Poetry/Pipfile lockfiles and npm
range resolution are deliberately out of v1 scope.

Out of scope is not the same as invisible. Every manifest recognized-but-unparsed
comes back as a :class:`CoverageGap` so the scanner can say which ecosystems went
unread, instead of returning the empty list that a genuinely clean project returns
(decisions.md D42).

Neither is *unreadable* the same as either of those. A directory the OS refuses to
list holds manifests this module will never see, and it used to drop them without a
word; those come back as :class:`ManifestProblem` for the caller to report (D69).
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from scanner.core.context import why_exception

_MANIFEST_NAMES = frozenset(
    {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json"}
)

#: Manifests we can recognize but not parse, as
#: ``name -> (OSV ecosystem, human label, is that ecosystem checked at all)``.
#:
#: The third field carries the distinction that makes the resulting finding
#: honest. ``False`` means the ecosystem is entirely out of scope. ``True`` means
#: the ecosystem *is* covered and only this declaration format is not — a
#: ``poetry.lock`` holds PyPI packages, so "this scan does not check PyPI" would
#: be a false statement about a tool that does.
_UNSUPPORTED_MANIFESTS: dict[str, tuple[str, str, bool]] = {
    "composer.json": ("Packagist", "Composer", False),
    "composer.lock": ("Packagist", "Composer", False),
    "go.mod": ("Go", "Go module", False),
    "go.sum": ("Go", "Go module", False),
    "Gemfile": ("RubyGems", "Bundler", False),
    "Gemfile.lock": ("RubyGems", "Bundler", False),
    "pom.xml": ("Maven", "Maven", False),
    "build.gradle": ("Maven", "Gradle", False),
    "build.gradle.kts": ("Maven", "Gradle", False),
    "Cargo.toml": ("crates.io", "Cargo", False),
    "Cargo.lock": ("crates.io", "Cargo", False),
    "packages.config": ("NuGet", "NuGet", False),
    "Pipfile": ("PyPI", "Pipenv", True),
    "Pipfile.lock": ("PyPI", "Pipenv", True),
    "poetry.lock": ("PyPI", "Poetry", True),
}

#: .NET project files are named after the project, so no name set can match them.
_UNSUPPORTED_SUFFIXES: tuple[tuple[str, tuple[str, str, bool]], ...] = (
    (".csproj", ("NuGet", "NuGet", False)),
    (".vbproj", ("NuGet", "NuGet", False)),
    (".fsproj", ("NuGet", "NuGet", False)),
)


@dataclass(frozen=True)
class Dependency:
    """One declared dependency. ``version`` is set only when it is exact."""

    ecosystem: str          # "PyPI" | "npm" (OSV ecosystem names)
    name: str               # canonical name for the ecosystem
    version: str | None
    manifest: str           # path to the manifest it came from
    line: int | None = None


@dataclass(frozen=True)
class CoverageGap:
    """A manifest that was found but not analysed.

    See ``_UNSUPPORTED_MANIFESTS`` for what ``ecosystem_checked`` means: it picks
    which of two different true sentences the report should say.
    """

    ecosystem: str
    label: str
    path: str
    ecosystem_checked: bool = False

    @property
    def group(self) -> tuple[str, str]:
        """The key findings are grouped by, so ``composer.json`` and
        ``composer.lock`` produce one "Composer was not checked" rather than two,
        while Poetry and Pipenv stay apart despite sharing an ecosystem."""
        return (self.ecosystem, self.label)


@dataclass(frozen=True)
class ManifestProblem:
    """A manifest, or a whole directory of them, that could not be read at all.

    Distinct from :class:`CoverageGap` in the way that matters to a reader: a gap
    is a decision this tool made and can describe ("Cargo is out of scope"), while
    a problem is the tool being stopped. Gaps become findings; problems become
    entries on ``ctx.errors``, which is what moves the run to exit 3.

    ``kind`` is one of ``unlistable-dir``, ``unreadable-file`` or ``unparseable``.
    Unlike the SAST walk's equivalent there is no subset of these that the caller
    may ignore: every one of them means a dependency set is smaller than it looks.
    """

    path: str
    kind: str
    detail: str


@dataclass(frozen=True)
class Discovery:
    """The result of one tree walk: what can be parsed, what cannot, and what
    could not even be looked at."""

    supported: list[Path]
    gaps: list[CoverageGap]
    problems: list[ManifestProblem] = field(default_factory=list)


# --- name normalization ---

def _normalize_pypi(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of ``-_.`` collapse to one ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


# --- version-exactness helpers ---

def _exact_pep440(constraint: str) -> str | None:
    """Return the version iff ``constraint`` is a single ``==x`` with no wildcard."""
    constraint = constraint.strip()
    if not constraint or "," in constraint:
        return None
    m = re.fullmatch(r"==\s*(\S+)", constraint)
    if not m:
        return None
    version = m.group(1)
    return None if "*" in version else version


def _parse_pep508(spec: str) -> tuple[str, str | None] | None:
    """Parse ``name[extras] <constraint> ; marker`` into (name, exact_version)."""
    spec = spec.split(";", 1)[0].strip()   # drop environment marker
    if not spec or "://" in spec or " @ " in spec:
        return None
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", spec)
    if not m:
        return None
    return m.group(1), _exact_pep440(m.group(2))


def _exact_npm(spec: str) -> str | None:
    """Return the version iff ``spec`` is a bare exact semver (no range operator)."""
    if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", spec.strip()):
        return spec.strip()
    return None


# --- per-format parsers ---

def parse_requirements_txt(text: str, manifest: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"\s+#.*$", "", raw).strip()   # strip inline comment
        if not line or line.startswith(("#", "-")):
            continue
        parsed = _parse_pep508(line)
        if parsed is None:
            continue
        name, version = parsed
        deps.append(Dependency("PyPI", _normalize_pypi(name), version, manifest, lineno))
    return deps


def parse_pyproject(text: str, manifest: str) -> list[Dependency]:
    data = tomllib.loads(text)
    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        specs.extend(group or [])
    deps: list[Dependency] = []
    for spec in specs:
        parsed = _parse_pep508(spec)
        if parsed is None:
            continue
        name, version = parsed
        deps.append(Dependency("PyPI", _normalize_pypi(name), version, manifest))
    return deps


def parse_package_json(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        for name, spec in (data.get(section) or {}).items():
            version = _exact_npm(spec) if isinstance(spec, str) else None
            deps.append(Dependency("npm", name, version, manifest))
    return deps


def parse_package_lock(text: str, manifest: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):   # lockfileVersion 2/3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or "node_modules/" not in path:
                continue
            name = path.split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                deps.append(Dependency("npm", name, version, manifest))
        return deps

    def walk(node: dict | None) -> None:   # lockfileVersion 1
        for name, meta in (node or {}).items():
            if isinstance(meta, dict):
                version = meta.get("version")
                if version:
                    deps.append(Dependency("npm", name, version, manifest))
                walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return deps


# --- dispatch + discovery ---

def parse_manifest(filename: str, text: str) -> list[Dependency]:
    base = os.path.basename(filename)
    if base == "package-lock.json":
        return parse_package_lock(text, filename)
    if base == "package.json":
        return parse_package_json(text, filename)
    if base == "pyproject.toml":
        return parse_pyproject(text, filename)
    if base == "requirements.txt" or (
        base.startswith("requirements") and base.endswith(".txt")
    ):
        return parse_requirements_txt(text, filename)
    return []


def pyproject_coverage_gap(path: str, text: str) -> CoverageGap | None:
    """A Poetry project whose dependencies :func:`parse_pyproject` cannot see.

    This is the worst shape the coverage problem takes. ``pyproject.toml`` is a
    *supported* manifest, so it is discovered, opened and parsed without
    complaint — but the parser reads PEP 621 tables, and Poetry declares under
    ``[tool.poetry.dependencies]``. The file yields zero dependencies, the scan
    reports nothing, and nothing anywhere says the project's entire dependency
    set went unread. An unrecognized file at least leaves no false impression.

    Returns ``None`` when a PEP 621 table is also present: those dependencies
    *were* read, so there is no gap to report even if Poetry metadata sits
    alongside them.
    """
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        # The parser is about to raise on the same text and that error is
        # reported on its own; do not pre-empt it with a misleading gap.
        return None
    if not ((data.get("tool") or {}).get("poetry") or {}).get("dependencies"):
        return None
    project = data.get("project") or {}
    if project.get("dependencies") or project.get("optional-dependencies"):
        return None
    return CoverageGap("PyPI", "Poetry", path, ecosystem_checked=True)


def _is_manifest(filename: str) -> bool:
    return filename in _MANIFEST_NAMES or (
        filename.startswith("requirements") and filename.endswith(".txt")
    )


def _unsupported_meta(filename: str) -> tuple[str, str, bool] | None:
    meta = _UNSUPPORTED_MANIFESTS.get(filename)
    if meta is not None:
        return meta
    for suffix, suffix_meta in _UNSUPPORTED_SUFFIXES:
        if filename.endswith(suffix):
            return suffix_meta
    return None


def discover(root, exclude_dirs=()) -> Discovery:
    """Walk ``root`` once, sorting manifests into parseable and merely recognized.

    Excluded directories are pruned for both halves: a ``composer.json`` vendored
    under ``node_modules`` is somebody else's dependency, and reporting it as a
    coverage gap in *this* project would be noise.

    ``os.walk`` swallows every error it meets unless given ``onerror``, so without
    one a directory the OS will not list is indistinguishable from an empty one and
    every manifest below it disappears from the result (D69). Problems come back on
    the result rather than through a sink argument, which is the difference between
    this function and the SAST walk: that one is a generator, so a returned value
    would arrive only after its caller stopped iterating.
    """
    exclude = set(exclude_dirs or ())
    supported: list[Path] = []
    gaps: list[CoverageGap] = []
    problems: list[ManifestProblem] = []

    def _unlistable(err: OSError) -> None:
        problems.append(ManifestProblem(
            str(getattr(err, "filename", None) or root),
            "unlistable-dir",
            why_exception(err),
        ))

    for dirpath, dirnames, filenames in os.walk(root, onerror=_unlistable):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for fn in sorted(filenames):
            if _is_manifest(fn):
                supported.append(Path(dirpath) / fn)
                continue
            meta = _unsupported_meta(fn)
            if meta is not None:
                ecosystem, label, checked = meta
                gaps.append(
                    CoverageGap(ecosystem, label, str(Path(dirpath) / fn), checked)
                )
    return Discovery(supported, gaps, problems)


def discover_manifests(root, exclude_dirs=()) -> list[Path]:
    """Walk ``root`` for recognized manifests, pruning ``exclude_dirs`` by name.

    The narrow "what can I parse" view of :func:`discover`. It discards both the
    coverage gaps *and* the problems, so a caller using this cannot tell a tree
    with no manifests from one it was not allowed to read. Nothing in the scanner
    calls it for that reason; anything that reports coverage wants ``discover``.
    """
    return discover(root, exclude_dirs).supported
