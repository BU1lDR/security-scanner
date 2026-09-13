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

# The frozen v1 config surface (contract §14). Scanner-specific detail keys may
# grow as each scanner is built; the shapes here match the documented namespace.
DEFAULTS: dict[str, Any] = {
    "scope": {
        "allowed_hosts": [],
        "active_allowlist": [],
        "authorized_ack": False,
    },
    "http": {
        "user_agent": "secscan/0.1 (+https://github.com/security-scanner)",
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
        "exclude_dirs": [".git", "node_modules", ".venv", "dist", "build"],
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
