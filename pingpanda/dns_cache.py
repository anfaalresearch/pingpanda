"""Concurrency-safe DNS caching for supplementary address lookups."""

from __future__ import annotations

import asyncio
import math
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Awaitable, Callable

DEFAULT_DNS_CACHE_TTL = 60.0
DEFAULT_DNS_NEGATIVE_TTL = 5.0
DEFAULT_DNS_CACHE_SIZE = 256


@dataclass(frozen=True)
class _CacheEntry:
    value: str | None
    expires_at: float


Resolver = Callable[[str, int], Awaitable[str | None]]


class DnsCache:
    """Bounded TTL cache with single-flight DNS lookup deduplication.

    Cache state belongs to one scan. Concurrent callers for the same host and
    port share one in-flight lookup. Cancelling one waiter does not cancel the
    shared lookup for the remaining callers.
    """

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_DNS_CACHE_TTL,
        negative_ttl: float = DEFAULT_DNS_NEGATIVE_TTL,
        max_entries: int = DEFAULT_DNS_CACHE_SIZE,
        timeout: float = 10.0,
        resolver: Resolver | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if (
            isinstance(ttl, bool)
            or not isinstance(ttl, (int, float))
            or not math.isfinite(ttl)
            or ttl < 0
        ):
            raise ValueError("DNS cache TTL must be a finite, non-negative number")
        if (
            isinstance(negative_ttl, bool)
            or not isinstance(negative_ttl, (int, float))
            or not math.isfinite(negative_ttl)
            or negative_ttl < 0
        ):
            raise ValueError(
                "DNS negative-cache TTL must be a finite, non-negative number"
            )
        if isinstance(max_entries, bool) or not isinstance(max_entries, int):
            raise ValueError("DNS cache size must be a positive integer")
        if max_entries <= 0:
            raise ValueError("DNS cache size must be a positive integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("DNS timeout must be a finite, positive number")

        self.ttl = float(ttl)
        self.negative_ttl = float(negative_ttl)
        self.max_entries = max_entries
        self.timeout = float(timeout)
        self._resolver = resolver or self._lookup
        self._clock = clock
        self._entries: OrderedDict[tuple[str, int], _CacheEntry] = OrderedDict()
        self._inflight: dict[tuple[str, int], asyncio.Task[str | None]] = {}

    @staticmethod
    def _key(hostname: str, port: int) -> tuple[str, int]:
        return hostname.rstrip(".").lower(), port

    def _get_cached(self, key: tuple[str, int]) -> tuple[bool, str | None]:
        entry = self._entries.get(key)
        if entry is None:
            return False, None

        if entry.expires_at <= self._clock():
            del self._entries[key]
            return False, None

        self._entries.move_to_end(key)
        return True, entry.value

    def _store(self, key: tuple[str, int], value: str | None) -> None:
        ttl = self.ttl if value is not None else self.negative_ttl

        # A zero TTL intentionally disables caching while still preserving
        # single-flight deduplication for simultaneous callers.
        if ttl == 0:
            self._entries.pop(key, None)
            return

        now = self._clock()
        expired = [
            cached_key
            for cached_key, entry in self._entries.items()
            if entry.expires_at <= now
        ]
        for cached_key in expired:
            del self._entries[cached_key]

        self._entries[key] = _CacheEntry(value=value, expires_at=now + ttl)
        self._entries.move_to_end(key)

        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    async def resolve(self, hostname: str, port: int) -> str | None:
        """Resolve a host/port using TTL caching and single-flight sharing."""
        key = self._key(hostname, port)

        hit, value = self._get_cached(key)
        if hit:
            return value

        # There is deliberately no await between the in-flight lookup and task
        # creation. Within one asyncio event loop this makes task registration
        # atomic and prevents duplicate lookups for the same key.
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.create_task(self._resolve_and_store(key))
            self._inflight[key] = task

        # Shield the shared task so cancelling one caller does not cancel the
        # lookup awaited by other workers.
        return await asyncio.shield(task)

    async def _resolve_and_store(self, key: tuple[str, int]) -> str | None:
        hostname, port = key
        try:
            try:
                value = await self._resolver(hostname, port)
            except (OSError, ValueError, asyncio.TimeoutError):
                value = None

            self._store(key, value)
            return value
        finally:
            current = asyncio.current_task()
            if self._inflight.get(key) is current:
                del self._inflight[key]

    async def _lookup(self, hostname: str, port: int) -> str | None:
        loop = asyncio.get_running_loop()
        addresses = await asyncio.wait_for(
            loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
            timeout=self.timeout,
        )

        if not addresses:
            return None

        ip_address = addresses[0][4][0]
        if ":" in ip_address:
            return f"[{ip_address}]:{port}"
        return f"{ip_address}:{port}"

    @property
    def entry_count(self) -> int:
        """Number of currently stored positive and negative cache entries."""
        return len(self._entries)

    @property
    def inflight_count(self) -> int:
        """Number of DNS lookups currently shared by one or more callers."""
        return len(self._inflight)
