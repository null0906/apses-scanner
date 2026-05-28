from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from urllib.parse import urlparse


class RateLimiter:
    """Per-host concurrency and token-bucket style request pacing."""

    def __init__(self, max_concurrency: int = 2, rate_limit_rps: float = 2.0):
        self.max_concurrency = max(1, int(max_concurrency))
        self.rate_limit_rps = max(0.1, float(rate_limit_rps))
        self._semaphores: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(self.max_concurrency))
        self._recent: dict[str, deque[float]] = defaultdict(deque)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def _host(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc or "default"

    async def acquire(self, url: str):
        host = self._host(url)
        sem = self._semaphores[host]
        await sem.acquire()
        try:
            async with self._locks[host]:
                window = self._recent[host]
                now = time.monotonic()
                while window and now - window[0] >= 1.0:
                    window.popleft()
                if len(window) >= self.rate_limit_rps:
                    delay = 1.0 - (now - window[0])
                    if delay > 0:
                        await asyncio.sleep(delay)
                    now = time.monotonic()
                    while window and now - window[0] >= 1.0:
                        window.popleft()
                window.append(time.monotonic())
            return _LimiterLease(sem)
        except Exception:
            sem.release()
            raise


class _LimiterLease:
    def __init__(self, semaphore: asyncio.Semaphore):
        self._semaphore = semaphore

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._semaphore.release()
        return False
