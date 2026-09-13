"""AI advice flows through the one HTTP choke point, and can't escape the allowlist."""

import asyncio

import httpx
import pytest

from scanner.ai.advisor import Advisor
from scanner.ai.provider import AnthropicProvider
from scanner.core.egress import Egress
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.gate import OutOfScopeError, RequestGate
from scanner.core.http import AsyncHttpClient
from scanner.core.location import Location
from scanner.core.scope import Scope


def _finding():
    return Finding(
        rule_id="sast.sink.python-eval",
        title="Use of eval()",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        location=Location.for_file("app.py", line=4),
        evidence="data = eval(req.body)",
        remediation="Avoid eval().",
        scanner="sast",
        references=["CWE-95"],
    )


def test_advice_flows_through_the_egress_gate():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-api-key")
        return httpx.Response(200, json={"content": [{"type": "text", "text": "Fix it by X."}]})

    transport = httpx.MockTransport(handler)

    async def run():
        gate = RequestGate(scope=Scope(), egress=Egress())  # api.anthropic.com is egress
        async with AsyncHttpClient(gate, transport=transport) as http:
            provider = AnthropicProvider(http, api_key="sk-int", model="claude-sonnet-5")
            findings = [_finding()]
            await Advisor(provider).advise(findings)
            return findings

    findings = asyncio.run(run())
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["key"] == "sk-int"
    assert findings[0].fix.description == "Fix it by X."


def test_ai_traffic_to_a_non_allowlisted_host_is_refused():
    """A provider pointed anywhere but the allowlist is stopped by the gate,
    before any network I/O — the AI layer cannot be used to reach arbitrary hosts."""

    def handler(request):  # pragma: no cover - must never be reached
        raise AssertionError("request should have been refused before sending")

    transport = httpx.MockTransport(handler)

    async def run():
        gate = RequestGate(scope=Scope(allowed_hosts={"example.com"}), egress=Egress())
        async with AsyncHttpClient(gate, transport=transport) as http:
            with pytest.raises(OutOfScopeError):
                await http.post("https://evil.example/v1/messages", json={})

    asyncio.run(run())
