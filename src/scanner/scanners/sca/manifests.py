"""Finding and parsing dependency manifests into a normalized dependency list.

SCA is only meaningful for versions we actually know are present, so the parsers
extract a version *only when it is exact* — a pin (``==2.0.1``, an npm ``1.2.3``,
a lockfile entry). Ranges and unpinned entries yield ``version=None`` and are
carried through so the scanner can report "unpinned, cannot check" rather than
guessing. Lockfiles (``package-lock.json``) are where exact versions are richest.

Supported in v1: ``requirements.txt`` / ``pyproject.toml`` (PyPI) and
``package.json`` / ``package-lock.json`` (npm). Poetry/Pipfile lockfiles and npm
range resolution are deliberately out of v1 scope.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

_MANIFEST_NAMES = frozenset(
    {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json"}
)


@dataclass(frozen=True)
class Dependency:
    """One declared dependency. ``version`` is set only when it is exact."""

    ecosystem: str          # "PyPI" | "npm" (OSV ecosystem names)
    name: str               # canonical name for the ecosystem
    version: str | None
    manifest: str           # path to the manifest it came from
    line: int | None = None


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


def _is_manifest(filename: str) -> bool:
    return filename in _MANIFEST_NAMES or (
        filename.startswith("requirements") and filename.endswith(".txt")
    )


def discover_manifests(root, exclude_dirs=()) -> list[Path]:
    """Walk ``root`` for recognized manifests, pruning ``exclude_dirs`` by name."""
    exclude = set(exclude_dirs or ())
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for fn in filenames:
            if _is_manifest(fn):
                found.append(Path(dirpath) / fn)
    return found
