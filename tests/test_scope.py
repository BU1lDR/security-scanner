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


# ── how a host string is compared ────────────────────────────────────────────
#
# Everything this class does is a host-string comparison against a default-deny
# set, so both sides have to be spelled the same way before the denials mean
# anything. See D60.

def test_a_capitalised_host_in_the_config_still_matches_its_own_target():
    """`urlparse` lowercases the host it parses; `allowed_hosts` is whatever a person
    typed into a file. Raw comparison made `Example.com` match nothing at all, so a
    config file that reads as correct produced a scan that refused every request to
    the host it named."""
    scope = Scope(allowed_hosts={"Example.COM"})
    assert scope.allows("https://example.com/login")


def test_the_fully_qualified_spelling_of_a_host_is_the_same_host():
    scope = Scope(allowed_hosts={"example.com"})
    assert scope.allows("https://example.com./login")


def test_a_capitalised_active_allowlist_entry_still_authorizes():
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"Example.com"},
        authorized_ack=True,
    )
    assert scope.active_allowed("https://example.com/")


def test_subdomains_are_out_of_scope_by_default():
    scope = Scope(allowed_hosts={"example.com"})
    assert not scope.allows("https://sub.example.com/")


def test_allow_subdomains_puts_a_subdomain_in_scope():
    scope = Scope(allowed_hosts={"example.com"}, allow_subdomains=True)
    assert scope.allows("https://sub.example.com/")
    assert scope.allows("https://deep.sub.example.com/")
    assert scope.allows("https://example.com/")  # still the host itself


def test_allow_subdomains_does_not_match_a_lookalike_domain():
    """The leading dot is the whole guarantee. Without it `notexample.com` ends with
    `example.com`, and typo-squatting domains are registered precisely because that
    suffix test gets written without it."""
    scope = Scope(allowed_hosts={"example.com"}, allow_subdomains=True)
    assert not scope.allows("https://notexample.com/")
    assert not scope.allows("https://example.com.evil.net/")
    assert not scope.allows("https://example.como/")


def test_allow_subdomains_does_not_widen_the_active_allowlist():
    """The load-bearing asymmetry. Widening what may be *read* finds more pages;
    widening what may be *probed* aims attack-shaped traffic at a host the operator
    never named, and that one is not reversible from the target's side."""
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"},
        authorized_ack=True,
        allow_subdomains=True,
    )
    assert scope.allows("https://admin.example.com/")           # in scope to read
    assert not scope.active_allowed("https://admin.example.com/")  # never probed
    assert scope.active_allowed("https://example.com/")


def test_an_explicitly_listed_subdomain_is_still_active_authorized():
    """The other direction: the rule above must refuse hosts nobody named, not hosts
    the operator went to the trouble of naming."""
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"admin.example.com"},
        authorized_ack=True,
        allow_subdomains=True,
    )
    assert scope.active_allowed("https://admin.example.com/")
