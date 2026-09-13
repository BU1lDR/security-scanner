"""A token-bucket rate limiter (contract §13).

One process-wide limiter paces all traffic to a single host so scanners cannot
collectively overload the target. The bucket holds up to ``capacity`` tokens and
refills at ``rate`` tokens per second; each request spends one token, waiting
just long enough when the bucket is empty.

The clock and sleep function are injectable so the pacing logic can be tested
deterministically without real time passing.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class TokenBucket:
    def __init__(
        self,
        rate: float,
        capacity: float | None = None,
        *,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be positive, got {rate!r}")
        self.rate = float(rate)
        # Default capacity is the per-second rate, but never below 1 so a single
        # request can always proceed even at sub-1/s rates.
        self.capacity = float(capacity) if capacity is not None else max(1.0, self.rate)
        self._tokens = self.capacity
        self._now = now
        self._sleep = sleep
        self._updated = now()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Consume one token, sleeping until one is available.

        The lock serializes waiters so concurrent callers are paced in order
        rather than all waking on the same refill."""
        async with self._lock:
            while True:
                now = self._now()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await self._sleep((1.0 - self._tokens) / self.rate)
