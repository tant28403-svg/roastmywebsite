import asyncio

from roastmywebsite.core.rate_limit import AsyncTokenBucket


async def test_acquire_does_not_block_forever():
    bucket = AsyncTokenBucket(rate=100.0, capacity=10.0)
    await asyncio.wait_for(bucket.acquire(), timeout=1.0)
    assert bucket.tokens >= 0


async def test_acquire_multiple():
    bucket = AsyncTokenBucket(rate=100.0, capacity=10.0)
    await asyncio.gather(*(bucket.acquire() for _ in range(5)))
    assert bucket.tokens >= 0