"""The one grammar for rule IDs (contract §5).

A rule ID is lowercase, dot-separated, with at least three segments:

    <family>.<category>.<name>

``<family>`` is one of ``sca``, ``dast``, ``sast``. Each segment is one or more
groups of ``[a-z0-9]`` joined by single hyphens (so ``missing-hsts`` is fine,
``-hsts`` and ``missing hsts`` are not). Reports group by family and
de-duplication keys on the rule ID, so a single enforced grammar keeps both
working.
"""

from __future__ import annotations

import re

FAMILIES = ("sca", "dast", "sast")

_SEGMENT = r"[a-z0-9]+(?:-[a-z0-9]+)*"
_PATTERN = re.compile(rf"^(?:{'|'.join(FAMILIES)})(?:\.{_SEGMENT}){{2,}}$")


def is_valid(rule_id: str) -> bool:
    return bool(_PATTERN.match(rule_id))


def validate(rule_id: str) -> None:
    """Raise ``ValueError`` if ``rule_id`` does not match the grammar."""
    if not is_valid(rule_id):
        raise ValueError(
            f"Invalid rule_id {rule_id!r}: expected lowercase "
            f"'<family>.<category>.<name>' with family in {FAMILIES}."
        )


def family(rule_id: str) -> str:
    """The first segment (detection family). Raises if the id is invalid."""
    validate(rule_id)
    return rule_id.split(".", 1)[0]
