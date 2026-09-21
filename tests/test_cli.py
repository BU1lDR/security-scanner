import json
from pathlib import Path

import pytest

from scanner import USER_AGENT, __version__
from scanner.cli import main
from scanner.core.engine import Engine
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location
from scanner.core.registry import Registry
from scanner.core.scanner import Requires, Scanner


def _finding(rule_id="sast.secret.aws-access-key", severity=Severity.HIGH,
             confidence=Confidence.FIRM, scanner="sast", location=None):
    return Finding(
        rule_id=rule_id,
        title="hardcoded key",
        severity=severity,
        confidence=confidence,
        location=location or Location.for_file("app.py", line=3),
        evidence="AKIA...redacted",
        remediation="rotate the key",
        scanner=scanner,
    )


def _yielding(name, requires, findings):
    async def scan(self, ctx):
        for f in findings:
            yield f
    return type(name, (Scanner,), {"name": name, "requires": requires, "scan": scan})


def _engine_with(*scanner_classes):
    reg = Registry()
    for cls in scanner_classes:
        reg.register(cls)
    return Engine(registry=reg)


def _code_engine(findings):
    return _engine_with(_yielding("sast", Requires(code=True), findings))


# --- exit codes (D14) ---

def test_clean_scan_exits_zero_and_says_no_findings(tmp_path, capsys):
    code = main([str(tmp_path)], engine=_code_engine([]))
    assert code == 0
    assert "No findings" in capsys.readouterr().out


def test_finding_at_threshold_exits_one(tmp_path, capsys):
    code = main([str(tmp_path)], engine=_code_engine([_finding(severity=Severity.HIGH)]))
    assert code == 1
    assert "sast.secret.aws-access-key" in capsys.readouterr().out


def test_finding_below_threshold_exits_zero_but_is_still_reported(tmp_path, capsys):
    code = main([str(tmp_path)], engine=_code_engine([_finding(severity=Severity.LOW)]))
    assert code == 0
    assert "sast.secret.aws-access-key" in capsys.readouterr().out


def test_severity_threshold_override_makes_low_finding_fail(tmp_path):
    code = main(
        [str(tmp_path), "--severity-threshold", "low"],
        engine=_code_engine([_finding(severity=Severity.LOW)]),
    )
    assert code == 1


# --- formats ---

def test_json_format_is_parseable(tmp_path, capsys):
    code = main(
        [str(tmp_path), "--format", "json"],
        engine=_code_engine([_finding(severity=Severity.HIGH)]),
    )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["high"] == 1
    assert doc["findings"][0]["rule_id"] == "sast.secret.aws-access-key"


def test_missing_code_path_is_exit_two_and_does_not_scan(tmp_path, capsys):
    """A path that does not exist must fail, not scan nothing and pass.

    The regression this guards is a silent one: `secscan ./scr` for `./src` used
    to walk a tree that was not there, find nothing, and exit 0. A CI job wired
    to that is permanently green for a scan that never ran. Asserting on the exit
    code alone is not enough — a clean scan is also non-fatal — so this also
    asserts the engine was never reached.
    """
    scanned = []

    class _Tripwire(Engine):
        async def run(self, *a, **kw):            # pragma: no cover - must not run
            scanned.append(True)
            raise AssertionError("the engine ran against a path that does not exist")

    missing = tmp_path / "definitely-not-here"
    code = main([str(missing)], engine=_Tripwire())

    assert code == 2
    assert scanned == []
    err = capsys.readouterr().err
    assert "No such code path" in err
    # The resolved absolute path is in the message, because the usual cause is
    # being somewhere other than where you thought you were.
    assert str(missing.resolve()) in err


def test_existing_path_is_still_classified_as_code(tmp_path):
    """The guard above must not reject the valid case it sits next to."""
    assert main([str(tmp_path)], engine=_code_engine([])) == 0


def test_unknown_format_is_rejected_with_exit_two(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main([str(tmp_path), "--format", "bogus"], engine=_code_engine([]))
    assert exc.value.code == 2


def test_output_is_written_to_file(tmp_path):
    out = tmp_path / "report.json"
    code = main(
        [str(tmp_path), "--format", "json", "--output", str(out)],
        engine=_code_engine([_finding(severity=Severity.HIGH)]),
    )
    assert code == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["findings"][0]["rule_id"] == "sast.secret.aws-access-key"


# --- a report that cannot be written (D64) ---

class _CountingEngine(Engine):
    """Records whether the scan was ever started."""

    def __init__(self):
        super().__init__(registry=Registry())
        self.runs = 0

    async def run(self, target, **kwargs):
        self.runs += 1
        return await super().run(target, **kwargs)


def test_an_unwritable_output_path_is_refused_before_anything_is_scanned(tmp_path, capsys):
    """The scan is the expensive, externally-visible half: minutes of rate-limited
    requests to somebody else's machine. Spending it and then discarding the result
    on a mistyped directory is the wrong order, so `--output` is validated beside
    `--config`, before the engine is touched."""
    engine = _CountingEngine()
    code = main([str(tmp_path), "--output", str(tmp_path / "no" / "such" / "r.json")],
                engine=engine)
    assert code == 2
    assert engine.runs == 0, "a bad output path must cost no traffic at all"
    err = capsys.readouterr().err
    assert "cannot write the report" in err and "does not exist" in err


def test_an_output_path_that_is_a_directory_is_refused(tmp_path, capsys):
    engine = _CountingEngine()
    assert main([str(tmp_path), "--output", str(tmp_path)], engine=engine) == 2
    assert engine.runs == 0
    assert "it is a directory" in capsys.readouterr().err


def test_the_writability_check_leaves_the_filesystem_as_it_found_it(tmp_path):
    """It probes by opening, which is the only honest test on Windows — and an
    opening probe creates files. Two things it must not do: leave behind a file
    nobody asked for, and touch one that was already there."""
    fresh = tmp_path / "fresh.json"
    existing = tmp_path / "existing.json"
    existing.write_text("previous report", encoding="utf-8")
    empty = tmp_path / "empty.json"
    empty.touch()

    for path in (fresh, existing, empty):
        main([str(tmp_path), "--config", str(tmp_path / "nope.json"),
              "--output", str(path)], engine=_code_engine([]))

    assert not fresh.exists(), "the check created a file and did not remove it"
    assert existing.read_text(encoding="utf-8") == "previous report"
    # Empty and not ours: `existed` is what decides, not the size, because an empty
    # file the operator made is theirs.
    assert empty.exists()


def test_a_report_that_cannot_be_written_exits_two_not_one(tmp_path, capsys, monkeypatch):
    """Exit 1 means "findings at or above the threshold" (D14). A scan whose report
    went nowhere must not borrow that code: the operator's next action is to fix the
    path, not to fix the code. This is the case the pre-flight check cannot cover —
    the path stopped being writable after it passed — so it is a second guard rather
    than the same check twice."""
    out = tmp_path / "report.json"
    real = Path.write_text

    def exploding(self, *a, **kw):
        if self == out:
            raise OSError(13, "Permission denied")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "write_text", exploding)
    code = main([str(tmp_path), "--format", "json", "--output", str(out)],
                engine=_code_engine([_finding(severity=Severity.CRITICAL)]))
    assert code == 2, "a CRITICAL finding must not turn a failed write into exit 1"
    err = capsys.readouterr().err
    assert "could not be written" in err and "Permission denied" in err
    # The tally is the only part of a successful scan that survives, so it is said.
    assert "1 critical" in err and "1 findings" in err


# --- the version (D64) ---

def test_version_prints_the_one_definition_and_exits_zero(capsys):
    """A report with no version on it cannot be dated, and there was no way to ask.
    Asserted against `scanner.__version__` rather than a literal: a second spelling
    of a release number is a spelling that will be wrong (see `pyproject.toml`, which
    reads it from there for the same reason)."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"secscan {__version__}"


def test_the_version_printed_is_the_version_the_target_sees():
    """The two must not be able to drift: an operator reading their own access log
    and an operator reading a report have to be able to compare the two numbers."""
    assert __version__ in USER_AGENT


# --- failure handling ---

def test_bad_config_path_returns_two(tmp_path, capsys):
    code = main(
        [str(tmp_path), "--config", str(tmp_path / "nope.json")],
        engine=_code_engine([]),
    )
    assert code == 2
    assert capsys.readouterr().err  # an error message was printed


def test_engine_failure_returns_two(tmp_path, capsys):
    class _Boom:
        async def run(self, target, **kwargs):
            raise RuntimeError("engine exploded")

    code = main([str(tmp_path)], engine=_Boom())
    assert code == 2
    assert "engine exploded" in capsys.readouterr().err


# --- web targets & active gating ---

def test_url_target_is_scanned(capsys):
    web = _yielding("dast", Requires(url=True),
                    [_finding(rule_id="dast.headers.missing-hsts",
                              location=Location.for_url("https://example.com/"))])
    code = main(["https://example.com/"], engine=_engine_with(web))
    assert code == 1
    assert "dast.headers.missing-hsts" in capsys.readouterr().out


def test_a_bare_host_is_refused_instead_of_guessed_at(capsys):
    """`example.com` was promoted to `https://example.com`, and the only thing
    separating a hostname from a filename was a dot — so `app.py`, `main.sh`,
    `requirements.txt` and `web.app` were promoted too, and `_build_target` then
    added that stranger's host to `allowed_hosts` (D53). Asserting on the exit code
    alone is not enough, because a scan that found nothing is also non-fatal: this
    asserts the engine was never reached, so no packet could have left."""
    scanned = []

    class _Tripwire(Engine):
        async def run(self, *a, **kw):            # pragma: no cover - must not run
            scanned.append(True)
            raise AssertionError("the engine ran against a host nobody typed a scheme for")

    code = main(["example.com"], engine=_Tripwire())

    assert code == 2
    assert scanned == []
    err = capsys.readouterr().err
    assert "https://" in err, "the message must name the form that would work"


def test_a_filename_shaped_like_a_host_is_not_a_website(capsys):
    """The case that makes D53 a security fix rather than a tidy-up: `.py` is
    Paraguay's ccTLD, so this string is a registrable domain *and* the most common
    kind of filename. It must not become a scan target when the file is absent."""
    scanned = []

    class _Tripwire(Engine):
        async def run(self, *a, **kw):            # pragma: no cover - must not run
            scanned.append(True)
            raise AssertionError("a missing file was scanned as a website")

    assert main(["app.py"], engine=_Tripwire()) == 2
    assert scanned == []


def test_code_target_still_gets_an_http_client(tmp_path):
    # SCA runs on code-only targets but needs egress HTTP (OSV/registries). The
    # CLI must provide an HTTP client even when the target has no web surface.
    def scan(self, ctx):
        async def gen():
            if ctx.http is not None:
                yield _finding(
                    rule_id="sca.vuln.osv",
                    scanner="sca",
                    location=Location.for_dependency("PyPI", "x", "1.0"),
                )
        return gen()

    NeedsHttp = type("sca", (Scanner,),
                     {"name": "sca", "requires": Requires(code=True), "scan": scan})
    code = main([str(tmp_path)], engine=_engine_with(NeedsHttp))
    assert code == 1  # finding emitted => the scanner saw a non-None ctx.http


def test_active_without_ack_warns(tmp_path, capsys):
    code = main(["https://example.com/", "--active"], engine=_engine_with())
    assert code == 0
    err = capsys.readouterr().err
    assert "authoriz" in err.lower() and "ack" in err.lower()


# --- the config reaching the scope (D60) ---

class _ScopeRecorder(Engine):
    """Runs nothing; keeps the scope and the run kwargs the CLI built."""

    def __init__(self):
        super().__init__(registry=Registry())
        self.scope = None
        self.kwargs: dict = {}

    async def run(self, target, **kwargs):
        self.scope = target.scope
        self.kwargs = dict(kwargs)
        return await super().run(target, **kwargs)


def _config(tmp_path, body: str):
    path = tmp_path / "secscan.toml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_allow_subdomains_reaches_the_scope_the_gate_asks(tmp_path):
    """The setting is spelled under `dast.crawler` (contract §14 froze it there) and
    enforced by `Scope`, because the request gate consults the scope on every
    request. Asserted through the CLI because the wiring between those two is the
    part that did not exist: the key was in DEFAULTS and in the docs and was read by
    nothing at all (D60)."""
    cfg = _config(tmp_path, "[dast.crawler]\nallow_subdomains = true\n")
    engine = _ScopeRecorder()
    assert main(["https://example.com/", "--config", cfg], engine=engine) == 0
    assert engine.scope.allow_subdomains is True
    assert engine.scope.allows("https://sub.example.com/")


def test_the_default_keeps_subdomains_out_of_scope(tmp_path):
    engine = _ScopeRecorder()
    assert main(["https://example.com/"], engine=engine) == 0
    assert engine.scope.allow_subdomains is False
    assert not engine.scope.allows("https://sub.example.com/")


def test_allow_subdomains_does_not_extend_the_active_authorization(tmp_path):
    """`--active` authorizes the host the operator typed. With subdomains in scope it
    must keep authorizing exactly that host: a run of `--active https://example.com/`
    is not consent to probe `admin.example.com`."""
    cfg = _config(
        tmp_path,
        "[scope]\nauthorized_ack = true\n\n[dast.crawler]\nallow_subdomains = true\n",
    )
    engine = _ScopeRecorder()
    main(["https://example.com/", "--active", "--config", cfg], engine=engine)
    assert engine.scope.active_allowed("https://example.com/")
    assert not engine.scope.active_allowed("https://admin.example.com/")


# --- which of the three active conditions a flag actually owns (D63) ---

_ARMED = """
[scope]
allowed_hosts = ["example.com"]
active_allowlist = ["example.com"]
authorized_ack = true

[dast.active]
enabled = true
"""


def test_a_config_file_alone_arms_the_active_tier(tmp_path, capsys):
    """Contract §11 said `dast.active.enabled` was "set only via the `--active` CLI
    flag" for as long as the document existed, and it never was: `main` reads the
    *merged* config, so all three gating conditions are ordinary keys. Measured
    end-to-end this invocation sends probes. Pinned because the sentence that was
    wrong is the one a reader consults to decide whether a committed config file can
    put attack traffic on the wire without anybody typing anything. It can."""
    engine = _ScopeRecorder()
    assert main(["https://example.com/", "--config", _config(tmp_path, _ARMED)],
                engine=engine) == 0
    assert engine.kwargs.get("active_enabled") is True
    assert engine.scope.authorized_ack is True
    assert engine.scope.active_allowed("https://example.com/")
    # And silently: the warning exists for the opposite case, an active run with no
    # acknowledgment, so its absence here is part of the claim.
    assert "authoriz" not in capsys.readouterr().err.lower()


def test_the_config_route_is_still_fail_closed_on_each_condition(tmp_path):
    """The positive control above would also pass if the gate had simply stopped
    gating. Each condition removed on its own has to disarm the tier."""
    engine = _ScopeRecorder()
    without_enabled = _ARMED.replace("enabled = true", "enabled = false")
    main(["https://example.com/", "--config", _config(tmp_path, without_enabled)],
         engine=engine)
    assert engine.kwargs.get("active_enabled") is False

    engine = _ScopeRecorder()
    without_ack = _ARMED.replace("authorized_ack = true", "authorized_ack = false")
    main(["https://example.com/", "--config", _config(tmp_path, without_ack)],
         engine=engine)
    assert engine.scope.authorized_ack is False
    assert not engine.scope.active_allowed("https://example.com/")


def test_enabling_actives_in_a_file_allowlists_the_typed_host_and_only_it(tmp_path):
    """The third condition cannot be withheld from the typed host, and that is
    deliberate rather than a gap: `_build_target` adds it whenever actives are on,
    because naming a target is the strongest statement of intent there is. What it
    does *not* do is extend to the rest of `allowed_hosts` — so a config file that
    widens the crawl does not widen what may be probed."""
    cfg = _ARMED.replace('allowed_hosts = ["example.com"]',
                         'allowed_hosts = ["example.com", "other.test"]')
    cfg = cfg.replace('active_allowlist = ["example.com"]', "")
    engine = _ScopeRecorder()
    main(["https://example.com/", "--config", _config(tmp_path, cfg)], engine=engine)
    assert engine.scope.active_allowed("https://example.com/")
    assert engine.scope.allows("https://other.test/")
    assert not engine.scope.active_allowed("https://other.test/")
