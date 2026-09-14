import asyncio

from scanner.scanners.sca.manifests import Dependency
from scanner.scanners.sca.osv import OsvClient, Vulnerability, _parse_vuln


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


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


def _vuln(vid, name="django", fixed="2.2.28"):
    """A full OSV record, the shape /v1/query returns."""
    return {
        "id": vid,
        "summary": "Something bad",
        "details": "details",
        "aliases": [],
        "references": [{"type": "WEB", "url": "https://example.com/a"}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": name, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }


class _OsvHttp:
    """Speaks both real OSV endpoints: ``/v1/querybatch`` (returns ids only, as
    the real API does) and ``/v1/query`` (returns full records)."""

    def __init__(self, affected):
        self._affected = affected  # {(name, version): [full vuln dicts]}
        self.batch_posts = []
        self.query_posts = []
        self.gets = []

    async def post(self, url, json=None):
        if url.endswith("/querybatch"):
            self.batch_posts.append(json)
            results = []
            for q in json["queries"]:
                vulns = self._affected.get((q["package"]["name"], q["version"]), [])
                # the real batch endpoint returns only id + modified
                results.append({"vulns": [{"id": v["id"], "modified": "0"} for v in vulns]})
            return _Resp({"results": results})
        self.query_posts.append(json)
        key = (json["package"]["name"], json["version"])
        return _Resp({"vulns": self._affected.get(key, [])})

    async def get(self, url):  # pragma: no cover - must not be reached
        self.gets.append(url)
        raise AssertionError("per-vuln GET by id should no longer be needed")


def test_costs_one_followup_query_per_affected_package_not_one_per_vulnerability():
    """A single old package can carry dozens of advisories. Fetching each
    advisory by id costs 1 + (distinct vulns) round trips — ~180 for a handful
    of outdated packages, which is most of a scan's wall clock. Screen with the
    batch endpoint, then pull FULL records with one /v1/query per *affected*
    package: 1 + (affected packages)."""
    django = Dependency("PyPI", "django", "2.2.0", "r.txt", 1)
    clean = Dependency("PyPI", "requests", "2.31.0", "r.txt", 2)
    many = [_vuln(f"GHSA-x{i:04d}") for i in range(20)]
    http = _OsvHttp({("django", "2.2.0"): many})

    result = asyncio.run(OsvClient(http).find_vulns([django, clean]))

    assert len(http.batch_posts) == 1        # one screening request
    assert len(http.query_posts) == 1        # only the affected package
    assert http.query_posts[0]["package"]["name"] == "django"
    assert http.gets == []                   # never one fetch per advisory
    assert len(result[django]) == 20         # all 20 still reported
    assert result[django][0].fixed_for("django", "PyPI") == ("2.2.28",)
    assert clean not in result


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
    http = _OsvHttp(
        {("flask", "2.0.1"): [_vuln("GHSA-aaaa-bbbb-cccc", name="flask", fixed="2.0.2")]}
    )

    result = asyncio.run(OsvClient(http).find_vulns([flask, six]))

    # only the pinned dep was in the batch query
    assert len(http.batch_posts[0]["queries"]) == 1
    assert http.batch_posts[0]["queries"][0]["version"] == "2.0.1"
    assert list(result) == [flask]
    assert isinstance(result[flask][0], Vulnerability)
    assert result[flask][0].id == "GHSA-aaaa-bbbb-cccc"


def test_find_vulns_returns_empty_without_pinned_deps():
    six = Dependency("PyPI", "six", None, "r.txt", 1)
    http = _OsvHttp({})
    result = asyncio.run(OsvClient(http).find_vulns([six]))
    assert result == {}
    assert http.batch_posts == []  # nothing to ask about


def test_find_vulns_omits_deps_with_no_vulns():
    flask = Dependency("PyPI", "flask", "2.0.1", "r.txt", 1)
    clean = Dependency("PyPI", "requests", "2.31.0", "r.txt", 2)
    http = _OsvHttp({("flask", "2.0.1"): [_vuln("GHSA-aaaa-bbbb-cccc", name="flask")]})
    result = asyncio.run(OsvClient(http).find_vulns([flask, clean]))
    assert list(result) == [flask]
    assert len(http.query_posts) == 1  # the clean dep got no follow-up request
