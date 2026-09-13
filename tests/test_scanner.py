import asyncio
import inspect

import pytest

from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location
from scanner.core.scanner import Requires, Scanner
from scanner.core.target import Target


def _collect(agen):
    async def run():
        return [item async for item in agen]

    return asyncio.run(run())


class _WebScanner(Scanner):
    name = "web"
    requires = Requires(url=True)

    async def scan(self, ctx):
        return
        yield  # pragma: no cover - marks this as an async generator


class _CodeScanner(Scanner):
    name = "code"
    requires = Requires(code=True)

    async def scan(self, ctx):
        return
        yield  # pragma: no cover


class _UniversalScanner(Scanner):
    name = "universal"
    requires = Requires()

    async def scan(self, ctx):
        yield Finding(
            rule_id="sca.vuln.osv",
            title="x",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
            location=Location.for_dependency("PyPI", "x", version="1.0"),
            evidence="e",
            remediation="r",
            scanner="universal",
        )


def test_requires_defaults_to_no_requirements():
    r = Requires()
    assert r.url is False and r.code is False and r.active is False


def test_web_scanner_applies_only_when_a_url_is_present():
    assert _WebScanner.applicable(Target(url="https://example.com/"))
    assert not _WebScanner.applicable(Target(code_path="./repo"))


def test_code_scanner_applies_only_when_a_code_path_is_present():
    assert _CodeScanner.applicable(Target(code_path="./repo"))
    assert not _CodeScanner.applicable(Target(url="https://example.com/"))


def test_universal_scanner_applies_to_any_target():
    assert _UniversalScanner.applicable(Target(url="https://example.com/"))
    assert _UniversalScanner.applicable(Target(code_path="./repo"))


def test_scan_is_an_async_generator():
    assert inspect.isasyncgenfunction(_UniversalScanner.scan)


def test_scan_yields_findings():
    findings = _collect(_UniversalScanner().scan(ctx=None))
    assert len(findings) == 1
    assert findings[0].rule_id == "sca.vuln.osv"


def test_scanner_cannot_be_instantiated_without_a_scan_method():
    with pytest.raises(TypeError):
        Scanner()
