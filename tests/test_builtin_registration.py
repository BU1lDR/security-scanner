"""Importing the built-in scanners package registers every v1 scanner."""

from scanner.core.registry import registry


def test_all_builtin_scanners_register():
    import scanner.scanners  # noqa: F401  (import triggers registration)

    names = set(registry.names())
    assert {"sca", "dast", "dast-active", "sast"} <= names
