from __future__ import annotations

import asyncio
import time


class AsyncTokenBucket:
    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = max(rate, 0.1)
        self.capacity = capacity or max(rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, amount: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                wait = (amount - self.tokens) / self.rate
        await asyncio.sleep(wait)