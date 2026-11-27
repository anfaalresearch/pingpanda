"""Tests for the shared DNS cache and single-flight lookup behaviour."""

import asyncio

import pytest

from pingpanda.dns_cache import (
    DEFAULT_DNS_CACHE_SIZE,
    DEFAULT_DNS_CACHE_TTL,
    DEFAULT_DNS_NEGATIVE_TTL,
    DnsCache,
)


async def test_concurrent_same_host_uses_one_lookup():
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return f"203.0.113.10:{port}"

    cache = DnsCache(resolver=resolver)
    tasks = [
        asyncio.create_task(cache.resolve("Example.COM", 443))
        for _ in range(20)
    ]

    await started.wait()
    await asyncio.sleep(0)
    release.set()
    results = await asyncio.gather(*tasks)

    assert calls == 1
    assert results == ["203.0.113.10:443"] * 20
    assert cache.inflight_count == 0


async def test_different_hosts_can_resolve_concurrently():
    started = []
    both_started = asyncio.Event()

    async def resolver(hostname, port):
        started.append(hostname)
        if len(started) == 2:
            both_started.set()
        await both_started.wait()
        return f"203.0.113.{len(started)}:{port}"

    cache = DnsCache(resolver=resolver)

    await asyncio.wait_for(
        asyncio.gather(
            cache.resolve("one.test", 443),
            cache.resolve("two.test", 443),
        ),
        timeout=1,
    )

    assert set(started) == {"one.test", "two.test"}


async def test_positive_cache_hit_and_ttl_expiry():
    now = [100.0]
    calls = 0

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        return f"203.0.113.7:{port}"

    cache = DnsCache(ttl=10, resolver=resolver, clock=lambda: now[0])

    first = await cache.resolve("example.test", 443)
    second = await cache.resolve("example.test.", 443)

    assert first == second == "203.0.113.7:443"
    assert calls == 1

    now[0] = 110.0
    third = await cache.resolve("example.test", 443)

    assert third == "203.0.113.7:443"
    assert calls == 2


async def test_failed_lookup_is_negative_cached_then_retried():
    now = [50.0]
    calls = 0

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        raise OSError("DNS failure")

    cache = DnsCache(
        negative_ttl=5,
        resolver=resolver,
        clock=lambda: now[0],
    )

    assert await cache.resolve("missing.test", 443) is None
    assert await cache.resolve("missing.test", 443) is None
    assert calls == 1

    now[0] = 55.0
    assert await cache.resolve("missing.test", 443) is None
    assert calls == 2


async def test_zero_ttl_disables_sequential_cache_hits():
    calls = 0

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        return f"203.0.113.9:{port}"

    cache = DnsCache(ttl=0, resolver=resolver)

    await cache.resolve("example.test", 443)
    await cache.resolve("example.test", 443)

    assert calls == 2
    assert cache.entry_count == 0


async def test_cache_is_bounded_and_uses_lru_eviction():
    calls = []

    async def resolver(hostname, port):
        calls.append((hostname, port))
        return f"203.0.113.{len(calls)}:{port}"

    cache = DnsCache(max_entries=2, resolver=resolver)

    await cache.resolve("a.test", 443)
    await cache.resolve("b.test", 443)

    # Refresh A so B becomes the least recently used entry.
    await cache.resolve("a.test", 443)
    await cache.resolve("c.test", 443)

    assert cache.entry_count == 2

    await cache.resolve("b.test", 443)

    assert [host for host, _ in calls] == [
        "a.test",
        "b.test",
        "c.test",
        "b.test",
    ]


async def test_host_and_port_form_the_cache_key():
    calls = 0

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        return f"203.0.113.20:{port}"

    cache = DnsCache(resolver=resolver)

    assert await cache.resolve("example.test", 80) == "203.0.113.20:80"
    assert await cache.resolve("example.test", 443) == "203.0.113.20:443"
    assert calls == 2


async def test_cancelled_waiter_does_not_cancel_shared_lookup():
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return f"203.0.113.42:{port}"

    cache = DnsCache(resolver=resolver)

    first = asyncio.create_task(cache.resolve("shared.test", 443))
    await started.wait()
    second = asyncio.create_task(cache.resolve("shared.test", 443))
    await asyncio.sleep(0)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    assert cache.inflight_count == 1

    release.set()
    assert await second == "203.0.113.42:443"
    assert calls == 1
    assert cache.inflight_count == 0


async def test_failed_lookup_cleans_up_inflight_state():
    async def resolver(hostname, port):
        raise OSError("not found")

    cache = DnsCache(negative_ttl=0, resolver=resolver)

    assert await cache.resolve("missing.test", 443) is None
    assert cache.inflight_count == 0


def test_dns_cache_cli_defaults(checker):
    args = checker.parse_arguments([])

    assert args.dns_cache_ttl == DEFAULT_DNS_CACHE_TTL
    assert args.dns_negative_ttl == DEFAULT_DNS_NEGATIVE_TTL
    assert args.dns_cache_size == DEFAULT_DNS_CACHE_SIZE


def test_dns_cache_cli_options(checker):
    args = checker.parse_arguments(
        [
            "--dns-cache-ttl",
            "120",
            "--dns-negative-ttl",
            "2.5",
            "--dns-cache-size",
            "64",
        ]
    )

    assert args.dns_cache_ttl == 120.0
    assert args.dns_negative_ttl == 2.5
    assert args.dns_cache_size == 64


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--dns-cache-ttl", "-1"),
        ("--dns-negative-ttl", "-1"),
        ("--dns-cache-size", "0"),
        ("--dns-cache-size", "-2"),
    ],
)
def test_invalid_dns_cache_cli_options_are_rejected(checker, option, value):
    with pytest.raises(SystemExit):
        checker.parse_arguments([option, value])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ttl": -1},
        {"ttl": float("inf")},
        {"negative_ttl": -1},
        {"negative_ttl": float("nan")},
        {"max_entries": 0},
        {"max_entries": True},
        {"timeout": 0},
    ],
)
def test_dns_cache_rejects_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        DnsCache(**kwargs)


async def test_check_all_shares_one_dns_lookup_for_same_host(
    checker, mock_transport, monkeypatch
):
    import httpx

    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def resolver(hostname, port):
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return f"203.0.113.55:{port}"

    real_cache = DnsCache

    def cache_factory(**kwargs):
        return real_cache(resolver=resolver, **kwargs)

    monkeypatch.setattr(checker.network, "DnsCache", cache_factory)
    mock_transport(lambda request: httpx.Response(200))

    urls = [
        "https://same.test/a",
        "https://same.test/b",
        "https://same.test/c",
        "https://same.test/d",
    ]

    scan = asyncio.create_task(
        checker.check_all(urls, max_concurrent=4, show_progress=False)
    )

    await started.wait()
    await asyncio.sleep(0)
    release.set()

    results = await scan

    assert len(results) == 4
    assert calls == 1
    assert {result.ip_port for result in results.values()} == {
        "203.0.113.55:443"
    }
