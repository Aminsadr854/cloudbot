import asyncio
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, call, patch

import account_sync
import control_service
from store import Store


class AccountSyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.store = Mock()
        self.store.accounts.return_value = [
            {"id": n, "provider": p} for n, p in enumerate(
                ["hetzner", "linode", "vultr", "upcloud", "cloudferro", "hetzner"], 1)]
        self.execute = AsyncMock(return_value={})
        self.store.pending_sync.return_value = {}
        self.store.get_cache.return_value = {}

    async def test_every_resource_forced_globally_and_all_primary_ip_accounts(self):
        with patch.object(account_sync, "execute", self.execute):
            await account_sync.sync_accounts(lambda: self.store)
        self.assertEqual(self.execute.await_args_list, [
            call(op, {"refresh": True}, self.store) for op in
            ("all_servers", "all_floating_ips", "check_all_accounts")] + [
            call("hetzner_primary_ips", {"account_id": n, "refresh": True}, self.store)
            for n in (1, 6)])
        self.store.close.assert_called_once()

    async def test_failed_resource_does_not_block_remaining_resources(self):
        self.execute.side_effect = [RuntimeError("offline"), {}, {}, RuntimeError("offline"), {}]
        with patch.object(account_sync, "execute", self.execute):
            await account_sync.sync_accounts(lambda: self.store)
        self.assertEqual(self.execute.await_count, 5)
        self.store.close.assert_called_once()

    async def test_cancellation_closes_store(self):
        self.execute.side_effect = asyncio.CancelledError
        with patch.object(account_sync, "execute", self.execute):
            with self.assertRaises(asyncio.CancelledError):
                await account_sync.sync_accounts(lambda: self.store)
        self.store.close.assert_called_once()

    async def test_starts_immediately_then_repeats_hourly_after_failure(self):
        sync = AsyncMock(side_effect=[RuntimeError("offline"), None])
        sleep = AsyncMock(side_effect=[None, asyncio.CancelledError])
        with patch.object(account_sync, "sync_accounts", sync), \
                patch.object(account_sync.asyncio, "sleep", sleep):
            with self.assertRaises(asyncio.CancelledError):
                await account_sync.run_sync(lambda: self.store, interval=0)
        self.assertEqual(sync.await_count, 2)
        for args in sleep.await_args_list:
            self.assertEqual(args.args[0], account_sync.CHANGE_POLL_INTERVAL)

    async def test_changed_account_sync_is_scoped(self):
        with patch.object(account_sync, 'execute', self.execute):
            await account_sync.sync_accounts(lambda: self.store, account_ids={2})
        self.assertEqual(self.execute.await_args_list, [
            call(op, {'refresh': True, 'account_id': 2}, self.store) for op in
            ('all_servers', 'all_floating_ips', 'check_all_accounts')])

    async def test_mutation_wakes_worker_before_hourly_deadline(self):
        self.store.pending_sync.side_effect = [{}, {2: 'new'}, {}]
        sleep = AsyncMock(side_effect=[None, None, asyncio.CancelledError])
        sync = AsyncMock()
        with patch.object(account_sync, 'sync_accounts', sync), \
                patch.object(account_sync.asyncio, 'sleep', sleep):
            with self.assertRaises(asyncio.CancelledError):
                await account_sync.run_sync(lambda: self.store)
        self.assertEqual(sync.await_args_list, [call(unittest.mock.ANY),
                                                call(unittest.mock.ANY, account_ids={2})])
        self.store.acknowledge_sync.assert_any_call({2: 'new'})

    async def test_app_cleanup_cancels_background_task(self):
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def worker(factory):
            started.set()
            try:
                await asyncio.Future()
            finally:
                stopped.set()

        with patch.object(account_sync, "run_sync", worker):
            ctx = account_sync.account_sync_context(lambda: self.store, {})
            await anext(ctx)
            await started.wait()
            await ctx.aclose()
        self.assertTrue(stopped.is_set())


class PersistentSyncTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name + '/db'
        self.key = self.tmp.name + '/key'
        self.store = Store(self.path, key_path=self.key)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    async def test_account_changes_queue_across_connections_and_survive_inflight_sync(self):
        aid = self.store.add_account('test', 'linode', 'dummy')
        other = Store(self.path, key_path=self.key)
        try:
            pending = other.pending_sync()
            self.assertIn(aid, pending)
            self.store.set_account_note(aid, 'updated')
            other.acknowledge_sync(pending)
            self.assertIn(aid, other.pending_sync(), 'A later change must not be cleared')
            other.acknowledge_sync(other.pending_sync())
            self.assertEqual(other.pending_sync(), {})
            self.store.delete_account(aid)
            self.assertIn(0, other.pending_sync(), 'Deletion refreshes and prunes global inventory')
        finally:
            other.close()

    async def test_mutations_queue_but_reads_and_rejected_actions_do_not(self):
        aid = self.store.add_account('test', 'linode', 'dummy')
        self.store.acknowledge_sync(self.store.pending_sync())
        with patch.object(control_service, '_execute', AsyncMock(return_value={'ok': True})):
            await control_service.execute('power_server', {'account_id': aid}, self.store)
            self.assertIn(aid, self.store.pending_sync())
            self.store.acknowledge_sync(self.store.pending_sync())
            await control_service.execute('all_servers', {}, self.store)
            self.assertEqual(self.store.pending_sync(), {})
        with patch.object(control_service, '_execute', AsyncMock(side_effect=control_service.InputError('confirmation required'))):
            with self.assertRaises(control_service.InputError):
                await control_service.execute('delete_server', {'account_id': aid}, self.store)
        self.assertEqual(self.store.pending_sync(), {})
        status = await control_service.execute('sync_status', {}, self.store)
        self.assertFalse(status['pending'])
