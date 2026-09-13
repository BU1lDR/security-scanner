import pytest

from scanner.core.scope import Scope


def test_scope_allows_a_url_on_an_allowed_host():
    scope = Scope(allowed_hosts={"example.com"})
    assert scope.allows("https://example.com/login")


def test_scope_rejects_a_url_on_a_different_host():
    scope = Scope(allowed_hosts={"example.com"})
    assert not scope.allows("https://evil.com/")


def test_from_url_seeds_the_allowed_host():
    scope = Scope.from_url("https://example.com/path")
    assert scope.allows("https://example.com/other")
    assert not scope.allows("https://sub.example.com/")


def test_active_is_refused_without_authorization_ack():
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"},
        authorized_ack=False,
    )
    assert not scope.active_allowed("https://example.com/")


def test_active_is_refused_when_host_not_in_active_allowlist():
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist=set(),
        authorized_ack=True,
    )
    assert not scope.active_allowed("https://example.com/")


def test_active_is_refused_when_host_out_of_scope():
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"other.com"},
        authorized_ack=True,
    )
    assert not scope.active_allowed("https://other.com/")


def test_active_is_allowed_when_all_three_conditions_hold():
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"},
        authorized_ack=True,
    )
    assert scope.active_allowed("https://example.com/")


def test_active_defaults_are_fail_closed():
    scope = Scope.from_url("https://example.com/")
    assert not scope.active_allowed("https://example.com/")


def test_from_url_accepts_a_bare_host_without_a_scheme():
    # A scheme-less target must not silently become an empty deny-all scope.
    scope = Scope.from_url("example.com")
    assert scope.allows("https://example.com/anything")


def test_from_url_raises_on_a_hostless_url():
    with pytest.raises(ValueError):
        Scope.from_url("")
    with pytest.raises(ValueError):
        Scope.from_url("https://")
