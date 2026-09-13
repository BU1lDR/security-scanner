"""A machine-usable remediation attached to a finding.

Most findings only carry human advice (``remediation`` text). Some can carry a
structured ``Fix`` the tool could apply. Per project policy (decisions.md D12/
D18), only low-risk fixes may be auto-applied after the user confirms: bumping a
dependency version and inserting a config snippet. Anything touching real
application code is a diff the user must approve, never applied automatically —
so it can never be marked ``apply_safe``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FixKind(Enum):
    DEPENDENCY_BUMP = "dependency_bump"
    CONFIG_SNIPPET = "config_snippet"
    CODE_PATCH = "code_patch"
    MANUAL = "manual"


_AUTO_APPLICABLE = (FixKind.DEPENDENCY_BUMP, FixKind.CONFIG_SNIPPET)


@dataclass
class Fix:
    kind: FixKind
    description: str
    apply_safe: bool
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.apply_safe and self.kind not in _AUTO_APPLICABLE:
            raise ValueError(
                f"A {self.kind.value} fix can never be apply_safe; only "
                "dependency bumps and config snippets may be auto-applied."
            )
