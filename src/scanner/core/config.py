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
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scanner import USER_AGENT

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
        return cls.from_dict(raw)

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
