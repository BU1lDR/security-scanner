import pytest

from scanner.core.registry import Registry
from scanner.core.scanner import Requires, Scanner
from scanner.core.target import Target


def _make(cls_name, scanner_name, requires):
    async def scan(self, ctx):
        return
        yield  # pragma: no cover

    return type(cls_name, (Scanner,), {"name": scanner_name, "requires": requires, "scan": scan})


def test_register_and_get_by_name():
    reg = Registry()
    Web = _make("Web", "web", Requires(url=True))
    reg.register(Web)
    assert reg.get("web") is Web


def test_names_are_sorted():
    reg = Registry()
    reg.register(_make("Sast", "sast", Requires(code=True)))
    reg.register(_make("Dast", "dast", Requires(url=True)))
    assert reg.names() == ["dast", "sast"]


def test_duplicate_name_from_a_different_class_is_rejected():
    reg = Registry()
    reg.register(_make("A", "dup", Requires()))
    with pytest.raises(ValueError):
        reg.register(_make("B", "dup", Requires()))


def test_registering_the_same_class_twice_is_idempotent():
    reg = Registry()
    Web = _make("Web", "web", Requires(url=True))
    reg.register(Web)
    reg.register(Web)  # no error
    assert reg.names() == ["web"]


def test_get_unknown_name_raises():
    with pytest.raises(KeyError):
        Registry().get("nope")


def test_applicable_filters_by_target_surface():
    reg = Registry()
    reg.register(_make("Web", "web", Requires(url=True)))
    reg.register(_make("Code", "code", Requires(code=True)))
    applicable = reg.applicable(Target(url="https://example.com/"))
    assert [c.name for c in applicable] == ["web"]


def test_register_returns_the_class_so_it_works_as_a_decorator():
    reg = Registry()
    Web = _make("Web", "web", Requires(url=True))
    assert reg.register(Web) is Web
