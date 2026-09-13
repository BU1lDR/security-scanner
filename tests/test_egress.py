from scanner.core.egress import DEFAULT_EGRESS_HOSTS, Egress


def test_default_egress_allows_the_tools_own_data_sources():
    egress = Egress()
    assert egress.allows("https://api.osv.dev/v1/query")
    assert egress.allows("https://pypi.org/pypi/requests/json")
    assert egress.allows("https://registry.npmjs.org/left-pad")
    assert egress.allows("https://api.anthropic.com/v1/messages")


def test_default_egress_does_not_allow_an_arbitrary_target_host():
    assert not Egress().allows("https://example.com/")


def test_default_hosts_are_the_expected_set():
    assert DEFAULT_EGRESS_HOSTS == frozenset(
        {"api.osv.dev", "pypi.org", "registry.npmjs.org", "api.anthropic.com"}
    )


def test_custom_egress_replaces_the_host_set():
    egress = Egress(hosts=frozenset({"internal.mirror.local"}))
    assert egress.allows("https://internal.mirror.local/simple/")
    assert not egress.allows("https://api.osv.dev/v1/query")
