import asyncio

from scanner.core.finding import Confidence, Severity
from scanner.core.rule_id import is_valid
from scanner.scanners.dast.exposed import probe_exposed_files

_ENV_BODY = "SECRET_KEY=supersecret\nDB_PASSWORD=hunter2\n"
_GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n"


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeHttp:
    """Serves canned responses keyed by URL path; unknown paths get ``default``."""

    def __init__(self, by_path, default):
        self._by_path = by_path
        self._default = default
        self.gets = []

    async def get(self, url, **kwargs):
        self.gets.append(url)
        for path, resp in self._by_path.items():
            if url.endswith(path):
                return resp
        return self._default


def _run(url, http):
    """The whole result — findings *and* the probes that never completed."""
    return asyncio.run(probe_exposed_files(url, http))


def _findings(url, http):
    return _run(url, http).findings


def test_exposed_env_file_is_reported_high():
    http = _FakeHttp({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, "nope"))
    findings = _findings("https://example.com/", http)
    ids = {f.rule_id for f in findings}
    assert "dast.exposed.env-file" in ids
    env = next(f for f in findings if f.rule_id == "dast.exposed.env-file")
    assert is_valid(env.rule_id)
    assert env.severity is Severity.HIGH
    assert env.scanner == "dast"
    assert env.location.url.endswith("/.env")
    assert "supersecret" not in env.evidence  # secret VALUES must not be echoed
    assert env.fix is None


def test_exposed_git_config_is_reported():
    http = _FakeHttp({".git/config": _Resp(200, _GIT_CONFIG)}, default=_Resp(404, ""))
    findings = _findings("https://example.com/", http)
    assert "dast.exposed.git-dir" in {f.rule_id for f in findings}


def test_soft_404_site_is_not_a_false_positive():
    # Every path (baseline AND probes) returns 200 with the same friendly page.
    friendly = _Resp(200, "<html><body>Page not found, sorry!</body></html>")
    http = _FakeHttp({}, default=friendly)
    assert _findings("https://example.com/", http) == []


def test_200_without_the_content_signature_is_not_reported():
    # .env returns 200 but the body is an HTML page, not env vars.
    http = _FakeHttp({".env": _Resp(200, "<!doctype html><title>Home</title>")},
                     default=_Resp(404, ""))
    assert _findings("https://example.com/", http) == []


def test_probes_are_same_origin_only():
    http = _FakeHttp({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, ""))
    _run("https://example.com/some/deep/path", http)
    assert all(u.startswith("https://example.com/") for u in http.gets)


class _Flaky(_FakeHttp):
    """Raises for paths containing ``fail``, serves everything else normally."""

    def __init__(self, by_path, default, fail="fail"):
        super().__init__(by_path, default)
        self._fail = fail

    async def get(self, url, **kwargs):
        if self._fail in url:
            raise RuntimeError("connection reset")
        return await super().get(url, **kwargs)


class _Dead(_FakeHttp):
    """Refuses everything, the way a host that is not listening does."""

    async def get(self, url, **kwargs):
        self.gets.append(url)
        raise OSError("[Errno 111] Connection refused")


def test_a_probe_error_does_not_abort_the_rest():
    http = _Flaky({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, ""),
                  fail=".git/config")
    result = _run("https://example.com/", http)
    assert "dast.exposed.env-file" in {f.rule_id for f in result.findings}


def test_a_probe_error_is_recorded_and_not_just_survived():
    """The test above is the half of this that was already checked. Carrying on past a
    dead probe is right; doing it silently is not — the one probe that raised is the
    one path this check can say nothing about, and the report has to carry that."""
    http = _Flaky({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, ""),
                  fail=".git/config")
    result = _run("https://example.com/", http)
    failed = [p for p in result.problems if p.kind == "probe-failed"]
    assert [p.url for p in failed] == ["https://example.com/.git/config"]
    assert "RuntimeError" in failed[0].detail  # the class name, per why_exception


def test_a_host_that_refuses_everything_is_not_a_clean_bill_of_health():
    """The defect this closes. Every probe raised, so every one returned None, so the
    caller skipped it as "not a hit" and the check reported nothing found — identical
    output to a properly-secured site, for a host it never once reached."""
    http = _Dead({}, default=_Resp(404, ""))
    result = _run("https://example.com/", http)
    assert result.findings == []
    assert len(result.problems) == 4, [p.kind for p in result.problems]
    assert {p.kind for p in result.problems} == {"calibration-failed", "probe-failed"}
    assert all("Connection refused" in p.detail for p in result.problems)


def test_a_clean_site_reports_no_problems_at_all():
    """The other direction, and the reason the assertion above is a count rather than
    "not empty": if a fully-reachable site also recorded problems, the channel would
    say "incomplete" on every scan and mean nothing."""
    http = _FakeHttp({}, default=_Resp(404, "not found"))
    result = _run("https://example.com/", http)
    assert result.findings == []
    assert result.problems == []


def test_a_failed_calibration_says_the_precision_guard_was_off():
    """Losing the baseline does not cost one data point, it disables the soft-404
    suppression for every probe that follows — and it fails loud rather than quiet, so
    nobody goes looking. The probes still run; the report says they were unfiltered."""
    http = _Flaky({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, ""),
                  fail="secscan-calibration")
    result = _run("https://example.com/", http)
    assert "dast.exposed.env-file" in {f.rule_id for f in result.findings}
    problems = [p for p in result.problems if p.kind == "calibration-failed"]
    assert len(problems) == 1
    assert "unfiltered" in problems[0].detail
