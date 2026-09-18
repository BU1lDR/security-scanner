"""SCA coverage findings: what the scan did *not* look at (decisions.md D42).

The rule these all serve: "we found nothing" and "we could not look" must never
produce the same output. A manifest the parser does not understand used to be
dropped at discovery with no trace, so a PHP or Go project came back with an
empty SCA section that was indistinguishable from a clean one.

These tests drive the behaviour through ``ScaScanner`` rather than the helper
module, because the thing that matters is what reaches a report.
"""

import asyncio

from scanner.core.config import Config
from scanner.core.context import ScanContext
from scanner.core.finding import Confidence, Severity
from scanner.core.location import LocationKind
from scanner.core.target import Target
from scanner.scanners.sca.scanner import ScaScanner


class _Resp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _FakeHttp:
    """Answers the OSV screening query with "nothing affected"."""

    def __init__(self):
        self.posts = []

    async def post(self, url, json=None):
        self.posts.append((url, json))
        return _Resp({"results": []})


#: Distinct from ``None``, which is itself a value under test (no HTTP client).
_DEFAULT_HTTP = object()


def _ctx(tmp_path, http):
    target = Target(code_path=str(tmp_path))
    return ScanContext(
        target=target, scope=target.scope, http=http, config=Config.defaults()
    )


def _scan(tmp_path, http=_DEFAULT_HTTP):
    ctx = _ctx(tmp_path, _FakeHttp() if http is _DEFAULT_HTTP else http)

    async def run():
        return [f async for f in ScaScanner().scan(ctx)]

    return asyncio.run(run()), ctx


def _by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


_UNSUPPORTED = "sca.coverage.unsupported-manifest"
_NO_MANIFEST = "sca.coverage.no-manifest"
_UNPINNED = "sca.coverage.unpinned-dependency"


# --- unsupported manifests are named, not dropped ---------------------------

def test_composer_manifest_is_reported_as_unexamined(tmp_path):
    (tmp_path / "composer.json").write_text('{"require": {}}', encoding="utf-8")

    findings, _ = _scan(tmp_path)

    gaps = _by_rule(findings, _UNSUPPORTED)
    assert len(gaps) == 1
    f = gaps[0]
    assert f.severity is Severity.INFO
    assert f.confidence is Confidence.CONFIRMED
    assert f.scanner == "sca"
    assert f.location.kind is LocationKind.FILE
    assert f.location.path.endswith("composer.json")
    assert "Packagist" in f.evidence
    assert "composer.json" in f.evidence
    # the point of the finding: absence of findings is not absence of risk
    assert "not evidence" in f.remediation


def test_composer_json_and_lock_collapse_into_one_finding(tmp_path):
    # Two files, one ecosystem. A client report must say "Composer was not
    # checked" once, not once per file.
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")
    (tmp_path / "composer.lock").write_text("{}", encoding="utf-8")

    findings, _ = _scan(tmp_path)

    gaps = _by_rule(findings, _UNSUPPORTED)
    assert len(gaps) == 1
    assert "composer.json" in gaps[0].evidence
    assert "composer.lock" in gaps[0].evidence


def test_each_unsupported_ecosystem_gets_its_own_finding(tmp_path):
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")
    (tmp_path / "go.mod").write_text("module example.com/x\n", encoding="utf-8")
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n", encoding="utf-8")

    findings, _ = _scan(tmp_path)

    gaps = _by_rule(findings, _UNSUPPORTED)
    assert len(gaps) == 3
    ecosystems = {e for f in gaps for e in ("Packagist", "Go", "RubyGems") if e in f.evidence}
    assert ecosystems == {"Packagist", "Go", "RubyGems"}


def test_csproj_is_matched_by_suffix_not_by_exact_name(tmp_path):
    # NuGet project files are named after the project, so a name set cannot
    # match them.
    (tmp_path / "Billing.Api.csproj").write_text("<Project />", encoding="utf-8")

    gaps = _by_rule(_scan(tmp_path)[0], _UNSUPPORTED)

    assert len(gaps) == 1
    assert "NuGet" in gaps[0].evidence


def test_unsupported_manifest_inside_excluded_dir_is_ignored(tmp_path):
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "composer.json").write_text("{}", encoding="utf-8")

    findings, _ = _scan(tmp_path)

    assert _by_rule(findings, _UNSUPPORTED) == []


# --- a supported ecosystem with an unsupported *format* is a different claim -

def test_poetry_lock_does_not_claim_pypi_is_unchecked(tmp_path):
    # PyPI *is* covered. Saying "this scan does not check PyPI" would be false;
    # the honest claim is that Poetry's own declarations were not read.
    (tmp_path / "poetry.lock").write_text("# lock\n", encoding="utf-8")

    gaps = _by_rule(_scan(tmp_path)[0], _UNSUPPORTED)

    assert len(gaps) == 1
    assert "Poetry" in gaps[0].evidence
    assert "does not check the PyPI" not in gaps[0].evidence


def test_pyproject_declaring_only_poetry_deps_is_reported(tmp_path):
    # The worst case: pyproject.toml *is* a supported manifest, so it is read and
    # reported as understood, but Poetry declares under [tool.poetry.dependencies]
    # which the PEP 621 parser does not look at. Zero deps, zero findings, and
    # nothing to tell anyone the file was effectively skipped.
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "app"\n\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\nflask = "^2.0"\n',
        encoding="utf-8",
    )

    gaps = _by_rule(_scan(tmp_path)[0], _UNSUPPORTED)

    assert len(gaps) == 1
    assert "Poetry" in gaps[0].evidence
    assert gaps[0].location.path.endswith("pyproject.toml")


# --- nothing supported at all ----------------------------------------------

def test_no_supported_manifest_says_sca_did_not_run(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")

    findings, _ = _scan(tmp_path)

    notes = _by_rule(findings, _NO_MANIFEST)
    assert len(notes) == 1
    assert notes[0].severity is Severity.INFO
    assert "requirements.txt" in notes[0].evidence
    assert "not evidence" in notes[0].remediation or "not a clean result" in notes[0].remediation


def test_supported_manifest_produces_no_coverage_noise(tmp_path):
    # The guard against the fix becoming noise: a fully pinned, fully supported
    # project must emit no coverage findings at all.
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

    findings, _ = _scan(tmp_path)

    assert _by_rule(findings, _NO_MANIFEST) == []
    assert _by_rule(findings, _UNSUPPORTED) == []
    assert _by_rule(findings, _UNPINNED) == []


# --- unpinned dependencies -------------------------------------------------

def test_unpinned_dependencies_are_reported_as_unchecked(tmp_path):
    # manifests.py documents that unpinned entries are "carried through so the
    # scanner can report 'unpinned, cannot check' rather than guessing". This is
    # that report.
    (tmp_path / "requirements.txt").write_text(
        "flask>=2.0\nrequests==2.31.0\nurllib3~=1.26\n", encoding="utf-8"
    )

    findings, _ = _scan(tmp_path)

    unpinned = _by_rule(findings, _UNPINNED)
    assert len(unpinned) == 1
    f = unpinned[0]
    assert f.severity is Severity.INFO
    assert f.location.path.endswith("requirements.txt")
    assert "flask" in f.evidence
    assert "urllib3" in f.evidence
    assert "requests" not in f.evidence      # pinned, so it *was* checked


def test_unpinned_dependencies_are_still_never_queried(tmp_path):
    # The old behaviour that was correct and must survive: a range has no single
    # version, so it must not be sent to OSV.
    (tmp_path / "requirements.txt").write_text("flask>=2.0\n", encoding="utf-8")
    http = _FakeHttp()

    findings, _ = _scan(tmp_path, http)

    assert http.posts == []
    assert len(_by_rule(findings, _UNPINNED)) == 1


def test_unpinned_findings_are_grouped_per_manifest(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask>=2.0\nboto3>=1.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "^4.17.0"}}', encoding="utf-8"
    )

    unpinned = _by_rule(_scan(tmp_path)[0], _UNPINNED)

    assert len(unpinned) == 2
    paths = sorted(f.location.path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for f in unpinned)
    assert paths == ["package.json", "requirements.txt"]


# --- fault isolation between the coverage pass and the OSV pass ------------

def test_coverage_findings_survive_an_osv_failure(tmp_path):
    # An OSV outage must not also erase "Composer was not checked". Those are
    # independent facts, so they are independent checks.
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

    class _Boom:
        async def post(self, *a, **k):
            raise RuntimeError("network down")

    findings, ctx = _scan(tmp_path, _Boom())

    assert len(_by_rule(findings, _UNSUPPORTED)) == 1
    assert len(ctx.errors) == 1
    assert ctx.errors[0].check == "osv"


def test_resolved_deps_with_no_http_client_records_an_error(tmp_path):
    # Dependencies were found and then abandoned. Returning [] here is the exact
    # shape of the bug: a clean-looking SCA section for a scan that never ran.
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

    findings, ctx = _scan(tmp_path, None)

    assert len(ctx.errors) == 1
    assert ctx.errors[0].scanner == "sca"
    assert "flask" in ctx.errors[0].message or "1 dependenc" in ctx.errors[0].message
    assert _by_rule(findings, _NO_MANIFEST) == []
