import asyncio
import unittest
from unittest.mock import AsyncMock
from menu_cache import MenuCache


class MenuCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cache = MenuCache(ttl=60)
        self.account = {'id': 1, 'provider': 'hetzner', 'token': 'test'}

    async def test_repeated_navigation_is_local_and_copy_isolated(self):
        load = AsyncMock(return_value=[{'id': 1}])
        first = await self.cache.get(self.account, 'ips', load)
        first[0]['id'] = 99
        self.assertEqual(await self.cache.get(self.account, 'ips', load), [{'id': 1}])
        load.assert_awaited_once()

    async def test_cold_requests_share_one_fetch(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def load():
            entered.set()
            await release.wait()
            return [1]
        loader = AsyncMock(side_effect=load)
        one = asyncio.create_task(self.cache.get(self.account, 'ips', loader))
        await entered.wait()
        two = asyncio.create_task(self.cache.get(self.account, 'ips', loader))
        await asyncio.sleep(0)
        release.set()
        self.assertEqual(await asyncio.gather(one, two), [[1], [1]])
        loader.assert_awaited_once()

    async def test_stale_value_returns_before_background_refresh_finishes(self):
        await self.cache.get(self.account, 'ips', AsyncMock(return_value=['old']))
        key = (1, self.cache.revision(self.account), 'ips')
        self.cache.entries[key] = (['old'], 0)
        entered, release = asyncio.Event(), asyncio.Event()
        async def load():
            entered.set()
            await release.wait()
            return ['new']
        self.assertEqual(await self.cache.get(self.account, 'ips', load), ['old'])
        await entered.wait()
        self.assertEqual(self.cache.peek(self.account, 'ips'), ['old'])
        release.set()
        await asyncio.gather(*self.cache.tasks.values())
        self.assertEqual(self.cache.peek(self.account, 'ips'), ['new'])

    async def test_mutation_discards_inflight_response(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def load():
            entered.set()
            await release.wait()
            return ['old']
        task = asyncio.create_task(self.cache.get(self.account, 'ips', load))
        await entered.wait()
        self.cache.invalidate(1)
        fresh = await self.cache.get(self.account, 'ips', AsyncMock(return_value=['new']))
        release.set()
        with self.assertRaises(RuntimeError):
            await task
        self.assertEqual(fresh, ['new'])
        self.assertEqual(self.cache.peek(self.account, 'ips'), ['new'])

    async def test_credential_change_does_not_revert_to_old_account(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def load():
            entered.set()
            await release.wait()
            return ['old']
        task = asyncio.create_task(self.cache.get(self.account, 'ips', load))
        await entered.wait()
        updated = {**self.account, 'token': 'new'}
        await self.cache.get(updated, 'ips', AsyncMock(return_value=['new']))
        release.set()
        with self.assertRaises(RuntimeError):
            await task
        self.assertEqual(self.cache.peek(updated, 'ips'), ['new'])

    async def test_refresh_failure_keeps_previous_snapshot(self):
        await self.cache.get(self.account, 'ips', AsyncMock(return_value=['old']))
        with self.assertRaises(OSError):
            await self.cache.get(self.account, 'ips', AsyncMock(side_effect=OSError()), force=True)
        self.assertEqual(self.cache.peek(self.account, 'ips'), ['old'])

    async def test_cancelled_menu_does_not_cancel_shared_fetch(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def load():
            entered.set()
            await release.wait()
            return ['new']
        task = asyncio.create_task(self.cache.get(self.account, 'ips', load))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        await asyncio.gather(*self.cache.tasks.values())
        self.assertEqual(self.cache.peek(self.account, 'ips'), ['new'])
