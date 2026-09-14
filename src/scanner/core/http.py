"""The single outbound-HTTP choke point (contract §9 + §13).

Every request a scanner makes goes through :meth:`AsyncHttpClient.request`. It
first asks the :class:`~scanner.core.gate.RequestGate` whether the request is
authorized, and if so whether it is *target* traffic (subject to the per-target
rate limit and concurrency cap) or *infrastructure egress* (its own gentler
budget). Anything the gate refuses raises :class:`OutOfScopeError` **before any
network I/O happens**.

Scanners must use only ``ctx.http``; opening a private ``httpx`` client (or a raw
socket that skips this gate) is forbidden. There is exactly one sanctioned
raw-socket path — the certificate probe in ``scanner.scanners.dast.tls``, which
needs a handshake httpx will not expose — and it is not an exemption from the
rule: it is handed this client's :attr:`gate` and must authorize through it before
connecting, on *stricter* terms than a request made here (an in-scope target host
only, never an infrastructure egress host). See §9 and decisions.md D45.
"""

from __future__ import annotations

import asyncio

import httpx

from scanner.core.gate import RequestClass, RequestGate
from scanner.core.rate_limit import TokenBucket

DEFAULT_USER_AGENT = "secscan/0.1 (+https://github.com/security-scanner)"


class AsyncHttpClient:
    def __init__(
        self,
        gate: RequestGate,
        *,
        user_agent: str = DEFAULT_USER_AGENT,
        per_host_rps: float = 2.0,
        concurrency: int = 10,
        timeout_s: float = 15.0,
        egress_rps: float = 1.0,
        egress_concurrency: int = 4,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.gate = gate
        # Target traffic: the rate the operator set, bounded by a concurrency cap.
        self.target_limiter = TokenBucket(per_host_rps)
        self._target_sem = asyncio.Semaphore(concurrency)
        # Infrastructure egress: a separate, gentler, independent budget (§13).
        self.egress_limiter = TokenBucket(egress_rps)
        self._egress_sem = asyncio.Semaphore(egress_concurrency)
        self._client = httpx.AsyncClient(
            headers={"user-agent": user_agent},
            timeout=httpx.Timeout(timeout_s),
            transport=transport,
            follow_redirects=False,
        )

    def _lane(self, request_class: RequestClass) -> tuple[TokenBucket, asyncio.Semaphore]:
        if request_class is RequestClass.EGRESS:
            return self.egress_limiter, self._egress_sem
        return self.target_limiter, self._target_sem

    async def request(
        self, method: str, url: str, *, active: bool = False, **kwargs
    ) -> httpx.Response:
        # Authorize first — raises OutOfScopeError before any network I/O.
        request_class = self.gate.authorize(url, active=active)
        limiter, semaphore = self._lane(request_class)
        await limiter.acquire()
        async with semaphore:
            return await self._client.request(method, url, **kwargs)

    async def get(self, url: str, *, active: bool = False, **kwargs) -> httpx.Response:
        return await self.request("GET", url, active=active, **kwargs)

    async def post(self, url: str, *, active: bool = False, **kwargs) -> httpx.Response:
        return await self.request("POST", url, active=active, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncHttpClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()
