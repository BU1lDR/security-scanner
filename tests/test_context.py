import asyncio

from scanner.core.context import ScanContext, ScanError
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location
from scanner.core.scope import Scope
from scanner.core.target import Target


def _ctx() -> ScanContext:
    return ScanContext(target=Target(url="https://example.com/"), scope=Scope.from_url("https://example.com/"))


def _finding() -> Finding:
    return Finding(
        rule_id="dast.headers.missing-hsts",
        title="t",
        severity=Severity.LOW,
        confidence=Confidence.FIRM,
        location=Location.for_url("https://example.com/"),
        evidence="e",
        remediation="r",
        scanner="dast",
    )


def test_scan_error_stores_fields_with_default_traceback_none():
    err = ScanError(scanner="dast", check="headers", message="boom")
    assert err.scanner == "dast"
    assert err.check == "headers"
    assert err.message == "boom"
    assert err.traceback_str is None


def test_run_check_returns_findings_on_success():
    ctx = _ctx()

    async def ok():
        return [_finding()]

    result = asyncio.run(ctx.run_check("dast", "headers", ok()))
    assert len(result) == 1
    assert ctx.errors == []


def test_run_check_isolates_a_failing_check():
    ctx = _ctx()

    async def boom():
        raise RuntimeError("kaboom")

    result = asyncio.run(ctx.run_check("dast", "tls", boom()))
    assert result == []
    assert len(ctx.errors) == 1
    err = ctx.errors[0]
    assert err.scanner == "dast"
    assert err.check == "tls"
    assert "kaboom" in err.message
    assert err.traceback_str is not None


def test_emit_error_accumulates():
    ctx = _ctx()
    ctx.emit_error("sca", "osv", ValueError("a"))
    ctx.emit_error("sast", "secrets", KeyError("b"))
    assert [e.scanner for e in ctx.errors] == ["sca", "sast"]
