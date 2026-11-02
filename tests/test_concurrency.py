"""Tests that run several checks at the same time."""

import asyncio

import httpx
import pytest

KNOWN_DEFECT = "known defect - see the FOSSSoC-S1 issue tracker"


class _Barrier:
    """A tiny barrier, so that every request finishes at the same moment."""

    def __init__(self, count):
        self.count = count
        self.arrived = 0
        self.released = asyncio.Event()

    async def wait(self):
        self.arrived += 1
        if self.arrived >= self.count:
            self.released.set()
        await self.released.wait()


async def test_every_url_keeps_its_own_redirect_target(checker, fake_dns):
    urls = ["https://a.test/start", "https://b.test/start", "https://c.test/start"]
    targets = {url: url.replace("/start", "/final") for url in urls}
    barrier = _Barrier(len(urls))

    async def handler(request):
        url = str(request.url)
        if url in targets:
            await barrier.wait()
            return httpx.Response(302, headers={"Location": targets[url]})
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as session:
        results = await asyncio.gather(
            *[
                checker.check_url_status(session, index, url)
                for index, url in enumerate(urls)
            ]
        )

    assert sorted(result.redirect_to for result in results) == sorted(targets.values())
