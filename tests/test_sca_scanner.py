import asyncio
import os
from pathlib import Path

import pytest

from scanner.core.config import Config
from scanner.core.context import ScanContext
from scanner.core.finding import Confidence, Severity
from scanner.core.fix import FixKind
from scanner.core.location import LocationKind
from scanner.core.target import Target
from scanner.scanners.sca.scanner import ScaScanner, select_fixed_version

_GHSA = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "summary": "Flask session flaw",
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


class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _FakeHttp:
    """Stands in for both OSV endpoints: ``/v1/querybatch`` screens (ids only)
    and ``/v1/query`` returns the full records for one package."""

    def __init__(self, batch, vulns):
        self._batch = batch
        self._vulns = vulns
        self.posts = []

    async def post(self, url, json=None):
        self.posts.append((url, json))
        if url.endswith("/querybatch"):
            return _Resp(self._batch)
        name = json["package"]["name"]
        return _Resp(
            {
                "vulns": [
                    v
                    for v in self._vulns.values()
                    if any(
                        a.get("package", {}).get("name") == name
                        for a in v.get("affected", [])
                    )
                ]
            }
        )


def _ctx(tmp_path, http):
    target = Target(code_path=str(tmp_path))
    return ScanContext(target=target, scope=target.scope, http=http, config=Config.defaults())


def _collect(scanner, ctx):
    async def run():
        return [f async for f in scanner.scan(ctx)]
    return asyncio.run(run())


def _batch_one():
    return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]}


def test_vulnerable_pinned_dep_becomes_a_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    http = _FakeHttp(_batch_one(), {"GHSA-aaaa-bbbb-cccc": _GHSA})

    findings = _collect(ScaScanner(), _ctx(tmp_path, http))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "sca.vuln.ghsa-aaaa-bbbb-cccc"
    assert f.severity is Severity.CRITICAL          # CVSS 9.8
    assert f.confidence is Confidence.CONFIRMED
    assert f.scanner == "sca"
    assert f.location.kind is LocationKind.DEPENDENCY
    assert f.location.package == "flask"
    assert f.location.version == "2.0.1"
    assert f.location.path.endswith("requirements.txt")
    assert f.location.line == 1
    assert f.fix is not None
    assert f.fix.kind is FixKind.DEPENDENCY_BUMP
    assert f.fix.apply_safe is True
    assert f.fix.details["to"] == "2.0.2"
    assert any("osv.dev" in r for r in f.references)
    assert "CVE-2021-1234" in f.references


def test_unpinned_dep_is_not_queried_but_is_reported_as_unchecked(tmp_path):
    # This test used to assert ``findings == []``, which encoded the bug: not
    # querying a range is correct, but saying nothing about it made an unchecked
    # dependency look like a clean one. The silence is the part that changed; the
    # empty query list is the part that must not. See tests/test_sca_coverage.py.
    (tmp_path / "requirements.txt").write_text("flask>=2.0\n", encoding="utf-8")
    http = _FakeHttp({"results": []}, {})
    findings = _collect(ScaScanner(), _ctx(tmp_path, http))
    assert http.posts == []
    assert [f.rule_id for f in findings] == ["sca.coverage.unpinned-dependency"]
    assert [f.rule_id for f in findings if f.rule_id.startswith("sca.vuln.")] == []


def test_finding_without_a_fix_has_no_autofix(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    no_fix = {
        **_GHSA,
        "affected": [
            {
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }
    http = _FakeHttp(_batch_one(), {"GHSA-aaaa-bbbb-cccc": no_fix})
    findings = _collect(ScaScanner(), _ctx(tmp_path, http))
    assert len(findings) == 1
    assert findings[0].fix is None


def test_osv_failure_is_fault_isolated(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

    class _Boom:
        async def post(self, *a, **k):
            raise RuntimeError("network down")

        async def get(self, *a, **k):
            raise RuntimeError("network down")

    ctx = _ctx(tmp_path, _Boom())
    findings = _collect(ScaScanner(), ctx)
    assert findings == []
    assert len(ctx.errors) == 1
    assert ctx.errors[0].scanner == "sca"


def test_osv_error_response_is_reported_not_read_as_a_clean_project(tmp_path):
    """The end of the chain that matters: an OSV error must reach the *user*.
    Zero findings on its own is indistinguishable from a healthy project, so the
    recorded error is the only thing that stops "OSV was down" from being read
    as "nothing is vulnerable" (the report renders it under Errors)."""
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

    class _Unavailable:
        async def post(self, url, json=None):
            return _Resp({"code": 14, "message": "upstream unavailable"}, status_code=503)

    ctx = _ctx(tmp_path, _Unavailable())
    findings = _collect(ScaScanner(), ctx)

    assert findings == []
    assert len(ctx.errors) == 1
    assert "503" in ctx.errors[0].message


@pytest.mark.parametrize(
    "current,fixed,expected",
    [
        ("2.0.1", ("2.0.2",), "2.0.2"),
        ("2.0.1", ("1.5.0", "2.0.2", "3.0.0"), "2.0.2"),  # smallest fix above current
        ("2.0.1", ("1.0.0", "2.0.0"), None),              # all already <= current
        ("2.0.1", (), None),
    ],
)
def test_select_fixed_version_pypi(current, fixed, expected):
    assert select_fixed_version(current, fixed, "PyPI") == expected


def test_select_fixed_version_npm():
    assert select_fixed_version("4.17.20", ("4.17.21",), "npm") == "4.17.21"


# --- alias de-duplication (OSV returns the same vuln under GHSA/PYSEC/CVE ids) ---

def _affects_flask(fixed="0.12.3"):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": fixed})
    return [{"package": {"name": "flask", "ecosystem": "PyPI"},
             "ranges": [{"type": "ECOSYSTEM", "events": events}]}]


def test_alias_records_collapse_into_one_finding(tmp_path):
    # GHSA and PYSEC records describing CVE-2018-1000656 are the same real vuln;
    # they must not be reported twice just because their OSV ids differ.
    ghsa = {
        "id": "GHSA-562c-5r94-xh97",
        "summary": "Flask denial of service",
        "aliases": ["CVE-2018-1000656", "PYSEC-2018-66"],
        "references": [{"url": "https://example.com/ghsa"}],
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        "affected": _affects_flask(),
    }
    pysec = {
        "id": "PYSEC-2018-66",
        "summary": "Flask denial of service",
        "aliases": ["CVE-2018-1000656"],
        "references": [{"url": "https://example.com/pysec"}],
        "severity": [],
        "affected": _affects_flask(),
    }
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
    batch = {"results": [{"vulns": [{"id": "GHSA-562c-5r94-xh97"},
                                    {"id": "PYSEC-2018-66"}]}]}
    http = _FakeHttp(batch, {"GHSA-562c-5r94-xh97": ghsa, "PYSEC-2018-66": pysec})

    findings = _collect(ScaScanner(), _ctx(tmp_path, http))

    assert len(findings) == 1
    f = findings[0]
    # GHSA is the richest record, so it becomes the representative.
    assert f.rule_id == "sca.vuln.ghsa-562c-5r94-xh97"
    # the collapsed ids remain discoverable as references.
    assert "PYSEC-2018-66" in f.references
    assert "CVE-2018-1000656" in f.references


def test_distinct_vulns_in_same_package_stay_separate(tmp_path):
    a = {"id": "GHSA-aaaa-bbbb-cccc", "summary": "flaw A", "aliases": ["CVE-2021-1"],
         "references": [], "severity": [], "affected": _affects_flask()}
    b = {"id": "GHSA-dddd-eeee-ffff", "summary": "flaw B", "aliases": ["CVE-2021-2"],
         "references": [], "severity": [], "affected": _affects_flask()}
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
    batch = {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"},
                                    {"id": "GHSA-dddd-eeee-ffff"}]}]}
    http = _FakeHttp(batch, {"GHSA-aaaa-bbbb-cccc": a, "GHSA-dddd-eeee-ffff": b})

    findings = _collect(ScaScanner(), _ctx(tmp_path, http))

    assert len(findings) == 2


# ── one bad manifest is not a dead scan (D69) ──

def _affects_flask_0_12():
    return [{"package": {"name": "flask", "ecosystem": "PyPI"},
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"}, {"fixed": "2.0.2"}]}]}]


def test_an_unparseable_manifest_does_not_cancel_the_readable_ones(tmp_path):
    """The defect this entry is about: `_resolve` read and parsed every manifest
    in one unguarded loop, so the first TOMLDecodeError propagated to scan()'s
    handler and returned -- losing the other manifests and both checks with it."""
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    broken = tmp_path / "svc"
    broken.mkdir()
    (broken / "pyproject.toml").write_text("[project\nname = 'x'\n", encoding="utf-8")
    http = _FakeHttp(_batch_one(), {"GHSA-aaaa-bbbb-cccc": _GHSA})
    ctx = _ctx(tmp_path, http)

    findings = _collect(ScaScanner(), ctx)

    # The readable manifest was still queried and still produced its finding.
    assert [f.rule_id for f in findings] == ["sca.vuln.ghsa-aaaa-bbbb-cccc"]
    assert http.posts, "OSV was never queried, so the scan died before the check"
    # And the file that failed is named, on the channel that sets exit 3.
    assert len(ctx.errors) == 1
    err = ctx.errors[0]
    assert err.scanner == "sca"
    assert err.check.endswith("pyproject.toml")
    assert "unparseable" in err.message
    assert "TOMLDecodeError" in err.message


def test_coverage_findings_survive_an_unparseable_manifest(tmp_path):
    """The second casualty of the coarse guard, and the less obvious one: the
    coverage check runs off the same _resolve, so an unreadable file used to
    erase the report of what else went unchecked."""
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    ctx = _ctx(tmp_path, _FakeHttp({"results": [{}]}, {}))

    rule_ids = sorted(f.rule_id for f in _collect(ScaScanner(), ctx))

    assert rule_ids == [
        "sca.coverage.unpinned-dependency",
        "sca.coverage.unsupported-manifest",
    ]
    assert [e.check for e in ctx.errors] == ["package.json"]


def test_a_manifest_that_cannot_be_opened_is_a_failure_not_a_missing_manifest(
    tmp_path, monkeypatch
):
    """An OSError on read must not read back as "this project declares nothing".
    `supported_count` still counts the file, so no no-manifest finding appears --
    the truth is that a manifest is there and we failed on it, and both halves of
    that are said in their own channel."""
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    real = Path.read_text

    def fake(self, *args, **kwargs):
        if self.name == "requirements.txt":
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake)
    ctx = _ctx(tmp_path, _FakeHttp({"results": [{}]}, {}))

    findings = _collect(ScaScanner(), ctx)

    assert [f.rule_id for f in findings] == []
    assert "sca.coverage.no-manifest" not in [f.rule_id for f in findings]
    assert [(e.check, "unreadable-file" in e.message) for e in ctx.errors] == [
        ("requirements.txt", True)
    ]


def test_an_unlistable_directory_reaches_the_report_through_sca(tmp_path, monkeypatch):
    """discover() records it; this is the plumbing from there to ctx.errors."""
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    real = os.scandir

    def fake(path=".", *args, **kwargs):
        if os.path.basename(str(path).rstrip("\\/")) == "locked":
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", fake)
    http = _FakeHttp(_batch_one(), {"GHSA-aaaa-bbbb-cccc": _GHSA})
    ctx = _ctx(tmp_path, http)

    findings = _collect(ScaScanner(), ctx)

    assert [f.rule_id for f in findings] == ["sca.vuln.ghsa-aaaa-bbbb-cccc"]
    assert [(e.check, "unlistable-dir" in e.message) for e in ctx.errors] == [
        ("locked", True)
    ]


def test_a_scan_of_a_readable_tree_records_no_failures(tmp_path):
    """The other-direction control for all of the above."""
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package.json").write_text(
        '{"dependencies":{"lodash":"4.17.21"}}', encoding="utf-8"
    )
    http = _FakeHttp(_batch_one(), {"GHSA-aaaa-bbbb-cccc": _GHSA})
    ctx = _ctx(tmp_path, http)

    _collect(ScaScanner(), ctx)

    assert ctx.errors == []
    assert ctx.skipped == []
