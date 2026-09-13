import asyncio

from scanner.scanners.sca.manifests import Dependency
from scanner.scanners.sca.osv import OsvClient, Vulnerability, _parse_vuln


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeHttp:
    def __init__(self, batch, vulns):
        self._batch = batch
        self._vulns = vulns
        self.posts = []
        self.gets = []

    async def post(self, url, json=None):
        self.posts.append((url, json))
        return _Resp(self._batch)

    async def get(self, url):
        self.gets.append(url)
        vid = url.rsplit("/", 1)[-1]
        return _Resp(self._vulns[vid])


_GHSA = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "summary": "Flask session flaw",
    "details": "long details",
    "aliases": ["CVE-2021-1234"],
    "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"name": "flask", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.2"}]}],
        }
    ],
}


def test_parse_vuln_extracts_core_fields():
    v = _parse_vuln(_GHSA)
    assert v.id == "GHSA-aaaa-bbbb-cccc"
    assert v.aliases == ("CVE-2021-1234",)
    assert v.references == ("https://example.com/advisory",)
    assert v.cvss_vectors == ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",)
    assert v.fixed_for("flask", "PyPI") == ("2.0.2",)
    assert v.fixed_for("other", "PyPI") == ()


def test_find_vulns_only_queries_pinned_deps_and_maps_results():
    flask = Dependency("PyPI", "flask", "2.0.1", "r.txt", 1)
    six = Dependency("PyPI", "six", None, "r.txt", 2)  # unpinned -> not queried
    batch = {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]}
    http = _FakeHttp(batch, {"GHSA-aaaa-bbbb-cccc": _GHSA})

    result = asyncio.run(OsvClient(http).find_vulns([flask, six]))

    # only the pinned dep was in the batch query
    assert len(http.posts[0][1]["queries"]) == 1
    assert http.posts[0][1]["queries"][0]["version"] == "2.0.1"
    assert list(result) == [flask]
    assert isinstance(result[flask][0], Vulnerability)
    assert result[flask][0].id == "GHSA-aaaa-bbbb-cccc"


def test_find_vulns_returns_empty_without_pinned_deps():
    six = Dependency("PyPI", "six", None, "r.txt", 1)
    http = _FakeHttp({"results": []}, {})
    result = asyncio.run(OsvClient(http).find_vulns([six]))
    assert result == {}
    assert http.posts == []  # nothing to ask about


def test_find_vulns_omits_deps_with_no_vulns():
    flask = Dependency("PyPI", "flask", "2.0.1", "r.txt", 1)
    clean = Dependency("PyPI", "requests", "2.31.0", "r.txt", 2)
    batch = {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}, {"vulns": []}]}
    http = _FakeHttp(batch, {"GHSA-aaaa-bbbb-cccc": _GHSA})
    result = asyncio.run(OsvClient(http).find_vulns([flask, clean]))
    assert list(result) == [flask]
