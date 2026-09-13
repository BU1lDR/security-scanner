import pytest

from scanner.core.egress import Egress
from scanner.core.gate import OutOfScopeError, RequestClass, RequestGate
from scanner.core.scope import Scope


def _gate(**scope_kwargs):
    scope = Scope(**scope_kwargs)
    return RequestGate(scope=scope, egress=Egress())


def test_passive_request_to_in_scope_target_is_target_traffic():
    gate = _gate(allowed_hosts={"example.com"})
    assert gate.authorize("https://example.com/page") is RequestClass.TARGET


def test_passive_request_to_egress_host_is_infrastructure():
    gate = _gate(allowed_hosts={"example.com"})
    assert gate.authorize("https://api.osv.dev/v1/query") is RequestClass.EGRESS


def test_passive_request_to_unknown_host_is_refused():
    gate = _gate(allowed_hosts={"example.com"})
    with pytest.raises(OutOfScopeError):
        gate.authorize("https://evil.com/")


def test_active_request_to_authorized_target_is_allowed():
    gate = _gate(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"},
        authorized_ack=True,
    )
    assert gate.authorize("https://example.com/search", active=True) is RequestClass.TARGET


def test_active_request_without_ack_is_refused():
    gate = _gate(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"},
        authorized_ack=False,
    )
    with pytest.raises(OutOfScopeError):
        gate.authorize("https://example.com/search", active=True)


def test_active_request_to_non_active_allowlisted_host_is_refused():
    gate = _gate(
        allowed_hosts={"example.com"},
        active_allowlist=set(),
        authorized_ack=True,
    )
    with pytest.raises(OutOfScopeError):
        gate.authorize("https://example.com/search", active=True)


def test_active_request_to_egress_host_is_refused_even_if_misconfigured_into_scope():
    # Infrastructure hosts are never attack targets, even if an operator mistakenly
    # places an egress host into scope AND the active allowlist AND acknowledges.
    gate = _gate(
        allowed_hosts={"api.osv.dev"},
        active_allowlist={"api.osv.dev"},
        authorized_ack=True,
    )
    with pytest.raises(OutOfScopeError):
        gate.authorize("https://api.osv.dev/v1/query", active=True)


def test_non_http_scheme_is_refused():
    # The choke point only authorizes http/https, even to an in-scope or egress host.
    gate = _gate(allowed_hosts={"example.com"})
    with pytest.raises(OutOfScopeError):
        gate.authorize("file:///etc/passwd")
    with pytest.raises(OutOfScopeError):
        gate.authorize("ftp://example.com/x")
    with pytest.raises(OutOfScopeError):
        gate.authorize("gopher://api.osv.dev/")
