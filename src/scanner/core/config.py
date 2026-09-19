"""Configuration: a flat, top-level-per-area namespace (contract §14).

Settings are held as a nested dict but read with dotted keys
(``cfg.get("dast.active.enabled")``). A :class:`Config` always starts from the
built-in :data:`DEFAULTS`; file contents and CLI overrides are deep-merged on
top, so a partial override never wipes its sibling defaults.

Only TOML (via the stdlib ``tomllib``) and JSON are supported as file formats —
both are dependency-free. YAML is intentionally not supported in v1.
"""

from __future__ import annotations

import copy
import difflib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scanner import USER_AGENT
from scanner.core.finding import Confidence, Severity

#: Directory names pruned from any local walk, matched by name at any depth.
#:
#: One list, in one place, because there were three and they disagreed. This file
#: held five entries; sast/scanner.py and sca/scanner.py each held a seven-entry
#: copy adding ``venv`` and ``__pycache__``. Since a :class:`Config` always has
#: DEFAULTS merged in, ``cfg.get("sast.exclude_dirs", _DEFAULT_EXCLUDES)`` never
#: reached its own fallback — the five-entry list here won every real run and the
#: seven-entry copies were dead code that read as if they were in force. The
#: visible effect was that ``venv/`` and ``__pycache__/`` were scanned: point the
#: tool at a project laid out the ordinary way and it walked the whole
#: virtualenv, reporting findings in third-party code the user does not own.
#:
#: The two scanners now import this as their fallback, so the fallback and the
#: default cannot drift apart again, and ``sca.exclude_dirs`` is spelled out below
#: rather than left to a fallback — SAST and SCA were reading different lists.
DEFAULT_EXCLUDE_DIRS: list[str] = [
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
]

# The frozen v1 config surface (contract §14). Scanner-specific detail keys may
# grow as each scanner is built; the shapes here match the documented namespace.
DEFAULTS: dict[str, Any] = {
    "scope": {
        "allowed_hosts": [],
        "active_allowlist": [],
        "authorized_ack": False,
    },
    "http": {
        # From scanner/__init__.py, not spelled out here. The literal that used to
        # sit on this line was a second copy of the default User-Agent, and copies
        # drift: this one and the one in core/http.py both said "secscan/0.1" with
        # a dead repo URL long after the release was 1.0.0. An operator reading
        # that header to find out who is scanning them got a 404.
        "user_agent": USER_AGENT,
        "per_host_rps": 2.0,
        "concurrency": 10,
        "timeout_s": 15.0,
    },
    "reporting": {
        "format": "terminal",          # terminal | json | html
        "severity_threshold": "medium",  # findings >= this fail the run (D14)
    },
    "sca": {
        "enabled": True,
        "ecosystems": ["PyPI", "npm"],
        "exclude_dirs": list(DEFAULT_EXCLUDE_DIRS),
    },
    "dast": {
        "enabled": True,
        "crawler": {
            "max_depth": 2,
            "max_pages": 50,
            "allow_subdomains": False,
            "user_agent": None,        # None => fall back to http.user_agent
        },
        "tls": {"enabled": True},
        "exposed": {"enabled": True},
        "active": {
            "enabled": False,          # the --active flag flips this (§11)
            "checks": [],              # [] => all available active checks
            "include_post": False,
            "max_requests": 200,
        },
    },
    "sast": {
        "enabled": True,
        "exclude_dirs": list(DEFAULT_EXCLUDE_DIRS),
        "min_confidence": "tentative",
    },
    "ai": {
        "enabled": False,
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "max_findings": 25,        # cap AI calls per scan (cost bound; overflow logged)
        "max_tokens": 500,         # response budget per finding
    },
}


def unknown_keys(raw: dict, defaults: dict | None = None, prefix: str = "") -> list[str]:
    """Dotted paths in ``raw`` that do not exist in the config surface.

    A config file used to be able to say anything at all. ``exclude_dir`` instead
    of ``exclude_dirs`` was accepted, merged in beside the real key, and ignored —
    so the directory you asked to skip was scanned anyway and nothing said so.
    ``per_host_rate`` instead of ``per_host_rps`` left the target being hit at the
    default rate while the file on disk claimed otherwise. Both are settings whose
    whole purpose is to constrain what the tool does to someone else's machine.

    That is the same failure as [D42] and [D46] one layer out: not a wrong answer,
    an instruction that was never carried out and never reported. A security tool
    that silently declines to apply your exclusions is worse than one that has no
    exclusions, because you checked.

    Only key *names* are checked, not value types. ``per_host_rps = "fast"`` still
    gets through here and fails later in the rate limiter. Said plainly rather than
    implied away; keys are where the silent-no-op lives.
    """
    defaults = DEFAULTS if defaults is None else defaults
    bad: list[str] = []
    for key, value in raw.items():
        path = f"{prefix}{key}"
        if key not in defaults:
            bad.append(path)
            continue
        expected = defaults[key]
        if isinstance(value, dict) and isinstance(expected, dict):
            bad.extend(unknown_keys(value, expected, prefix=f"{path}."))
    return bad


#: Settings whose value comes from a closed set, and the set.
#:
#: Key names are not the only place a typo becomes a silent no-op.
#: ``dast.active.checks`` is filtered with ``{n: ALL_CHECKS[n] for n in names if n
#: in ALL_CHECKS}``, so one misspelt entry is dropped without comment — and if it
#: was the only entry, the active tier runs *no checks at all* while the operator
#: believes intrusive scanning is on and reads the empty result as "nothing found".
#: That is the worst direction for this particular mistake to fail in.
#:
#: Only closed sets are listed. Open-ended values (hosts, directory names, model
#: identifiers) cannot be checked here and are not pretended to be.
#: Two of these are *derived* from the enums that define them, not typed out
#: again. A hand-copied set here would be a fresh instance of the bug
#: :data:`DEFAULT_EXCLUDE_DIRS` exists to record — a second copy of a list, in a
#: place nobody thinks to update, silently winning. The remaining two cannot be
#: imported without a cycle (``reporting`` and the dast-active scanner both sit
#: above this module), so ``tests/test_config.py`` asserts they still agree
#: with their source of truth instead.
VALUE_CHOICES: dict[str, frozenset[str]] = {
    "reporting.format": frozenset({"terminal", "json", "html"}),
    "reporting.severity_threshold": frozenset(s.name.lower() for s in Severity),
    "sast.min_confidence": frozenset(c.name.lower() for c in Confidence),
    "sca.ecosystems": frozenset({"PyPI", "npm"}),
    "dast.active.checks": frozenset({"xss-reflected", "sqli-error", "open-redirect"}),
}


def bad_values(cfg: "Config") -> list[str]:
    """Human-readable complaints about settings outside their closed set."""
    problems: list[str] = []
    for key, allowed in VALUE_CHOICES.items():
        value = cfg.get(key)
        if value is None:
            continue
        given = value if isinstance(value, list) else [value]
        for item in given:
            if item in allowed:
                continue
            close = difflib.get_close_matches(str(item), sorted(allowed), n=1, cutoff=0.6)
            hint = f" (did you mean {close[0]!r}?)" if close else ""
            problems.append(
                f"  {key} = {item!r} is not one of "
                f"{', '.join(sorted(allowed))}{hint}"
            )
    return problems


def _did_you_mean(path: str) -> str:
    """The nearest real key at the same level, if there is an obvious one."""
    *parents, leaf = path.split(".")
    node: Any = DEFAULTS
    for part in parents:
        if not isinstance(node, dict) or part not in node:
            return ""
        node = node[part]
    if not isinstance(node, dict):
        return ""
    close = difflib.get_close_matches(leaf, list(node), n=1, cutoff=0.6)
    if not close:
        return ""
    prefix = ".".join(parents)
    return f" (did you mean {prefix + '.' if prefix else ''}{close[0]}?)"


def _deep_merge(base: dict, override: dict) -> dict:
    """Return a new dict with ``override`` layered onto ``base``; nested dicts
    merge recursively rather than replacing the whole subtree."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


@dataclass
class Config:
    data: dict

    @classmethod
    def defaults(cls) -> "Config":
        return cls(data=copy.deepcopy(DEFAULTS))

    @classmethod
    def from_dict(cls, overrides: dict) -> "Config":
        return cls(data=_deep_merge(DEFAULTS, overrides or {}))

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        """Read a TOML or JSON config file, rejecting keys that do not exist.

        Validation lives here rather than in :meth:`from_dict` because this is the
        one entry point fed by a human-written file. ``from_dict`` stays lenient:
        it is the internal merge constructor, called throughout the codebase and
        in tests with dicts that are known-good by construction.

        An unknown key is an error, not a warning, for the same reason an
        unsupported file format already is. A warning about a setting that was not
        applied is a line in a log nobody reads, and the settings most worth
        mistyping — ``exclude_dirs``, ``per_host_rps``, ``authorized_ack`` — are
        the ones that bound what this tool does to a machine that is not yours.
        """
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".toml":
            with path.open("rb") as fh:
                raw = tomllib.load(fh)
        elif suffix == ".json":
            raw = json.loads(path.read_text(encoding="utf-8"))
        else:
            raise ValueError(
                f"Unsupported config format {suffix!r}; use .toml or .json"
            )

        bad = unknown_keys(raw)
        if bad:
            listed = "\n".join(f"  {k}{_did_you_mean(k)}" for k in bad)
            raise ValueError(
                f"unknown setting(s) in {path.name}:\n{listed}\n"
                f"These would have been ignored silently. See docs/configuration.md "
                f"for every key this tool reads."
            )

        cfg = cls.from_dict(raw)
        wrong = bad_values(cfg)
        if wrong:
            raise ValueError(
                f"invalid setting value(s) in {path.name}:\n" + "\n".join(wrong)
            )
        return cfg

    def merged(self, overrides: dict) -> "Config":
        """Return a new Config with ``overrides`` layered on top of this one."""
        return Config(data=_deep_merge(self.data, overrides or {}))

    def get(self, key: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node
