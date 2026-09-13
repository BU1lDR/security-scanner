import json

import pytest

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


def test_bare_host_is_treated_as_url(capsys):
    web = _yielding("dast", Requires(url=True),
                    [_finding(rule_id="dast.headers.missing-hsts",
                              location=Location.for_url("https://example.com/"))])
    code = main(["example.com"], engine=_engine_with(web))
    assert code == 1


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
