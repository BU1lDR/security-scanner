import pytest

from scanner.core.target import Scope, Target


def test_scope_allows_a_url_on_an_allowed_host():
    scope = Scope(allowed_hosts={"example.com"})
    assert scope.allows("https://example.com/login")


def test_scope_rejects_a_url_on_a_different_host():
    scope = Scope(allowed_hosts={"example.com"})
    assert not scope.allows("https://evil.com/")


def test_scope_from_url_seeds_the_host_from_that_url():
    scope = Scope.from_url("https://example.com/path")
    assert scope.allows("https://example.com/other")


def test_scope_does_not_implicitly_allow_subdomains():
    scope = Scope.from_url("https://example.com/")
    assert not scope.allows("https://sub.example.com/")


def test_target_requires_a_url_or_a_code_path():
    with pytest.raises(ValueError):
        Target()


def test_target_reports_that_it_carries_a_web_surface_only():
    t = Target(url="https://example.com/")
    assert t.has_web
    assert not t.has_code


def test_target_reports_that_it_carries_a_code_surface_only():
    t = Target(code_path="./repo")
    assert t.has_code
    assert not t.has_web


def test_target_defaults_scope_to_the_url_host_when_none_given():
    t = Target(url="https://example.com/")
    assert t.scope.allows("https://example.com/x")
    assert not t.scope.allows("https://other.com/")


def test_has_web_is_false_for_an_empty_string_url():
    # An empty-string url is not a web surface; has_web must agree with the
    # truthiness check __post_init__ uses, or URL-only scanners get mis-selected.
    t = Target(url="", code_path="./repo")
    assert not t.has_web
    assert t.has_code
