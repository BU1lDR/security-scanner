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
    return asyncio.run(probe_exposed_files(url, http))


def test_exposed_env_file_is_reported_high():
    http = _FakeHttp({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, "nope"))
    findings = _run("https://example.com/", http)
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
    findings = _run("https://example.com/", http)
    assert "dast.exposed.git-dir" in {f.rule_id for f in findings}


def test_soft_404_site_is_not_a_false_positive():
    # Every path (baseline AND probes) returns 200 with the same friendly page.
    friendly = _Resp(200, "<html><body>Page not found, sorry!</body></html>")
    http = _FakeHttp({}, default=friendly)
    assert _run("https://example.com/", http) == []


def test_200_without_the_content_signature_is_not_reported():
    # .env returns 200 but the body is an HTML page, not env vars.
    http = _FakeHttp({".env": _Resp(200, "<!doctype html><title>Home</title>")},
                     default=_Resp(404, ""))
    assert _run("https://example.com/", http) == []


def test_probes_are_same_origin_only():
    http = _FakeHttp({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, ""))
    _run("https://example.com/some/deep/path", http)
    assert all(u.startswith("https://example.com/") for u in http.gets)


def test_a_probe_error_does_not_abort_the_rest():
    class _Flaky(_FakeHttp):
        async def get(self, url, **kwargs):
            if url.endswith(".git/config"):
                raise RuntimeError("connection reset")
            return await super().get(url, **kwargs)

    http = _Flaky({".env": _Resp(200, _ENV_BODY)}, default=_Resp(404, ""))
    findings = _run("https://example.com/", http)
    assert "dast.exposed.env-file" in {f.rule_id for f in findings}
