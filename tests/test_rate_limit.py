import asyncio

import pytest

from scanner.core.rate_limit import TokenBucket


class FakeClock:
    """A controllable clock. Time only advances when the bucket sleeps or when
    the test explicitly advances it, so rate-limiting is deterministic."""

    def __init__(self) -> None:
        self.t = 0.0

    def now(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        assert seconds >= 0
        self.t += seconds


def _drain(bucket: TokenBucket, n: int) -> None:
    for _ in range(n):
        asyncio.run(bucket.acquire())


def test_full_bucket_allows_a_burst_without_waiting():
    clock = FakeClock()
    bucket = TokenBucket(rate=1.0, capacity=3, now=clock.now, sleep=clock.sleep)
    for _ in range(3):
        asyncio.run(bucket.acquire())
    assert clock.t == 0.0  # burst up to capacity is free


def test_acquire_waits_when_empty():
    clock = FakeClock()
    bucket = TokenBucket(rate=2.0, capacity=2, now=clock.now, sleep=clock.sleep)
    _drain(bucket, 2)          # empty the bucket, no time passes
    assert clock.t == 0.0
    asyncio.run(bucket.acquire())  # must wait 1 token / 2 per-sec = 0.5s
    assert clock.t == pytest.approx(0.5)


def test_refills_over_elapsed_time():
    clock = FakeClock()
    bucket = TokenBucket(rate=2.0, capacity=2, now=clock.now, sleep=clock.sleep)
    _drain(bucket, 2)
    clock.t += 2.0                 # two seconds pass on their own
    asyncio.run(bucket.acquire())  # refilled to capacity -> no wait
    assert clock.t == 2.0


def test_capacity_defaults_to_rate():
    assert TokenBucket(rate=5.0).capacity == 5.0


def test_capacity_floor_is_one_for_slow_rates():
    # A sub-1/s rate must still let a single request through immediately.
    assert TokenBucket(rate=0.2).capacity == 1.0


def test_non_positive_rate_is_rejected():
    with pytest.raises(ValueError):
        TokenBucket(rate=0.0)
    with pytest.raises(ValueError):
        TokenBucket(rate=-1.0)
