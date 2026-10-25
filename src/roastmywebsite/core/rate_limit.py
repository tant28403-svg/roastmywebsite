from __future__ import annotations

import asyncio
import random
import time


class AsyncTokenBucket:
    def __init__(self, rate: float, capacity: float | None = None, jitter: float = 0.0):
        self.rate = max(rate, 0.1)
        self.capacity = capacity or max(rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()
        self.jitter = max(0.0, jitter)

    async def acquire(self, amount: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= amount:
                    self.tokens -= amount
                    break
                wait = (amount - self.tokens) / self.rate
            await asyncio.sleep(wait)
        if self.jitter > 0:
            await asyncio.sleep(random.uniform(0, self.jitter))