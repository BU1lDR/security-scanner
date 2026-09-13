import asyncio

import httpx
import pytest

from scanner.core.egress import Egress
from scanner.core.gate import OutOfScopeError, RequestClass
from scanner.core.http import AsyncHttpClient
from scanner.core.gate import RequestGate
from scanner.core.scope import Scope


class RecordingTransport(httpx.AsyncBaseTransport):
    """An in-memory transport that records requests and can hold them open to
    observe concurrency, so tests never touch the network."""

    def __init__(self, *, delay: float = 0.0) -> None:
        self.requests: list[httpx.Request] = []
        self.in_flight = 0
        self.max_in_flight = 0
        self.delay = delay

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
        finally:
            self.in_flight -= 1
        return httpx.Response(200, text="ok")


def _client(transport, scope=None, **kwargs) -> AsyncHttpClient:
    scope = scope if scope is not None else Scope(allowed_hosts={"example.com"})
    gate = RequestGate(scope=scope, egress=Egress())
    return AsyncHttpClient(gate, transport=transport, **kwargs)


def test_out_of_scope_request_raises_before_any_network_call():
    async def body():
        t = RecordingTransport()
        client = _client(t)
        with pytest.raises(OutOfScopeError):
            await client.get("https://evil.com/")
        assert t.requests == []  # the gate blocked it before the transport
        await client.aclose()

    asyncio.run(body())


def test_target_request_returns_response_and_sends_user_agent():
    async def body():
        t = RecordingTransport()
        client = _client(t, user_agent="secscan/test")
        resp = await client.get("https://example.com/path")
        assert resp.status_code == 200
        assert t.requests[0].headers["user-agent"] == "secscan/test"
        await client.aclose()

    asyncio.run(body())


def test_egress_host_is_allowed_even_when_out_of_scope():
    async def body():
        # api.osv.dev is not in scope, but it is an infrastructure egress host.
        t = RecordingTransport()
        client = _client(t)
        resp = await client.get("https://api.osv.dev/v1/query")
        assert resp.status_code == 200
        assert len(t.requests) == 1
        await client.aclose()

    asyncio.run(body())


def test_active_request_to_non_active_host_raises_before_network():
    async def body():
        # In scope for passive, but not active-authorized.
        t = RecordingTransport()
        client = _client(t, scope=Scope(allowed_hosts={"example.com"}))
        with pytest.raises(OutOfScopeError):
            await client.get("https://example.com/", active=True)
        assert t.requests == []
        await client.aclose()

    asyncio.run(body())


def test_active_request_allowed_when_fully_authorized():
    async def body():
        scope = Scope(
            allowed_hosts={"example.com"},
            active_allowlist={"example.com"},
            authorized_ack=True,
        )
        t = RecordingTransport()
        client = _client(t, scope=scope)
        resp = await client.get("https://example.com/", active=True)
        assert resp.status_code == 200
        await client.aclose()

    asyncio.run(body())


def test_target_and_egress_use_separate_lanes():
    async def body():
        client = _client(RecordingTransport())
        target_limiter, target_sem = client._lane(RequestClass.TARGET)
        egress_limiter, egress_sem = client._lane(RequestClass.EGRESS)
        assert target_limiter is client.target_limiter
        assert egress_limiter is client.egress_limiter
        assert target_limiter is not egress_limiter
        assert target_sem is not egress_sem
        await client.aclose()

    asyncio.run(body())


def test_concurrency_semaphore_bounds_in_flight_requests():
    async def body():
        t = RecordingTransport(delay=0.02)
        # High rate so the token bucket does not pace; concurrency is the only cap.
        client = _client(t, per_host_rps=1000.0, concurrency=2)
        await asyncio.gather(
            *[client.get(f"https://example.com/{i}") for i in range(6)]
        )
        assert t.max_in_flight <= 2
        assert len(t.requests) == 6
        await client.aclose()

    asyncio.run(body())


def test_post_uses_the_post_method():
    async def body():
        t = RecordingTransport()
        client = _client(t)
        await client.post("https://example.com/form", data={"a": "b"})
        assert t.requests[0].method == "POST"
        await client.aclose()

    asyncio.run(body())


def test_async_context_manager_closes_the_client():
    async def body():
        t = RecordingTransport()
        async with _client(t) as client:
            resp = await client.get("https://example.com/")
            assert resp.status_code == 200
        assert client._client.is_closed

    asyncio.run(body())
