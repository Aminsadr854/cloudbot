import importlib
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import providers


class PrimaryProviderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.p = providers.Provider({'provider': 'hetzner', 'token': 'test'})
        self.ip = {'id': 2, 'name': 'new', 'ip': '192.0.2.2', 'type': 'ipv4',
                   'assignee_id': None, 'location': {'name': 'nbg1'}}
        self.server = {'id': 9, 'status': 'off', 'location': {'name': 'nbg1'},
                       'public_net': {'ipv4': {'id': 1}}}
        self.p.hetzner_primary_ip = AsyncMock(return_value=self.ip)
        self.p._req = AsyncMock(return_value={'server': self.server})
        self.p._wait_hetzner_action = AsyncMock()

    async def test_all_pages(self):
        self.p._req.side_effect = [
            {'primary_ips': [{'id': 1}], 'meta': {'pagination': {'next_page': 2}}},
            {'primary_ips': [{'id': 2}], 'meta': {'pagination': {'next_page': None}}}]
        self.assertEqual(await self.p.hetzner_primary_ips(), [{'id': 1}, {'id': 2}])

    async def test_running_server_never_mutated(self):
        self.server['status'] = 'running'
        with self.assertRaises(providers.ProviderError):
            await self.p.assign_hetzner_primary_ip(2, 9)
        self.assertTrue(all(c.args[0] == 'GET' for c in self.p._req.call_args_list))

    async def test_wrong_location_never_mutated(self):
        self.ip['location']['name'] = 'hel1'
        with self.assertRaises(providers.ProviderError):
            await self.p.assign_hetzner_primary_ip(2, 9)
        self.p._req.assert_awaited_once()

    async def test_assigned_ip_cannot_be_stolen(self):
        self.ip['assignee_id'] = 10
        with self.assertRaises(providers.ProviderError):
            await self.p.assign_hetzner_primary_ip(2, 9)
        self.p._req.assert_not_awaited()

    async def test_replacement_preserves_old_allocation(self):
        self.p.update_hetzner_primary_ip = AsyncMock()
        self.p.unassign_hetzner_primary_ip = AsyncMock()
        await self.p.assign_hetzner_primary_ip(2, 9)
        self.p.update_hetzner_primary_ip.assert_awaited_once_with(1, auto_delete=False)
        self.p.unassign_hetzner_primary_ip.assert_awaited_once_with(1)
        self.assertEqual(self.p._req.call_args.args, ('POST', '/primary_ips/2/actions/assign'))

    async def test_failed_assignment_restores_old_ip(self):
        self.p.update_hetzner_primary_ip = AsyncMock()
        self.p.unassign_hetzner_primary_ip = AsyncMock()
        empty = {**self.server, 'public_net': {}}
        self.p._req.side_effect = [{'server': self.server}, providers.ProviderError('failed'),
                                  {'server': empty}, {'action': {'status': 'success'}}]
        with self.assertRaisesRegex(providers.ProviderError, 'restored'):
            await self.p.assign_hetzner_primary_ip(2, 9)
        self.assertEqual(self.p._req.call_args.args, ('POST', '/primary_ips/1/actions/assign'))

    async def test_uncertain_success_does_not_replace_new_ip(self):
        self.p.update_hetzner_primary_ip = AsyncMock()
        self.p.unassign_hetzner_primary_ip = AsyncMock()
        attached = {**self.server, 'public_net': {'ipv4': {'id': 2}}}
        self.p._req.side_effect = [{'server': self.server}, providers.ProviderError('timeout'),
                                  {'server': attached}]
        await self.p.assign_hetzner_primary_ip(2, 9)
        self.assertEqual(self.p._req.await_count, 3)

    async def test_deletion_requires_unassigned_unprotected_ip(self):
        for changes in ({'assignee_id': 9}, {'protection': {'delete': True}}):
            self.p.hetzner_primary_ip.return_value = {**self.ip, **changes}
            with self.assertRaises(providers.ProviderError):
                await self.p.delete_hetzner_primary_ip(2)
        self.p._req.assert_not_awaited()

    async def test_create_preserves_ip_and_uses_location(self):
        self.p._req.return_value = {'primary_ip': self.ip}
        await self.p.create_hetzner_primary_ip('nbg1', 'ipv4', 'new')
        payload = self.p._req.call_args.kwargs['json']
        self.assertEqual(payload['location'], 'nbg1')
        self.assertFalse(payload['auto_delete'])
        self.assertNotIn('assignee_id', payload)


class PrimaryBotTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = patch.dict(os.environ, {
            'CLOUDBOT_TOKEN': '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi',
            'CLOUDBOT_OWNER': '123', 'CLOUDBOT_DB': cls.tmp.name+'/db.sqlite',
            'CLOUDBOT_KEY': cls.tmp.name+'/key'})
        cls.env.start()
        cls.b = importlib.import_module('bot')

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.tmp.cleanup()

    def cb(self, data, owner=123):
        return SimpleNamespace(data=data, from_user=SimpleNamespace(id=owner),
            answer=AsyncMock(), message=SimpleNamespace(chat=SimpleNamespace(id=123),
                message_id=4, edit_text=AsyncMock()))

    async def test_owner_enforced(self):
        cb = self.cb('hp:list:1:0', owner=999)
        with patch.object(self.b.st, 'account') as account:
            await self.b.primary_manager(cb, AsyncMock())
            account.assert_not_called()

    async def test_confirmation_is_single_use(self):
        cb = self.cb('hp:ok:1:token')
        self.b.primary_confirmations['token'] = (self.b.time.monotonic()+300, 123, 4, 1, 'unassign', ['2'])
        p = SimpleNamespace(unassign_hetzner_primary_ip=AsyncMock())
        with patch.object(self.b.st, 'account', return_value={'id': 1, 'provider': 'hetzner'}), \
             patch.object(self.b.providers, 'Provider', return_value=p), \
             patch.object(self.b, 'remove_account_server_ip_cache', new=AsyncMock()), \
             patch.object(self.b, 'schedule_account_server_ip_cache_refresh'):
            await self.b.primary_manager(cb, AsyncMock())
            await self.b.primary_manager(cb, AsyncMock())
        p.unassign_hetzner_primary_ip.assert_awaited_once_with('2')

    async def test_partial_batch_stops_and_reports_allocations(self):
        cb = self.cb('hp:ok:1:batch')
        self.b.primary_confirmations['batch'] = (self.b.time.monotonic()+300, 123, 4, 1, 'create', ['nbg1', 'ipv4', 3])
        p = SimpleNamespace(create_hetzner_primary_ip=AsyncMock(side_effect=[
            {'ip': '192.0.2.2'}, providers.ProviderError('quota')]))
        with patch.object(self.b.st, 'account', return_value={'id': 1, 'provider': 'hetzner'}), \
             patch.object(self.b.providers, 'Provider', return_value=p), \
             patch.object(self.b, 'remove_account_server_ip_cache', new=AsyncMock()), \
             patch.object(self.b, 'schedule_account_server_ip_cache_refresh'):
            await self.b.primary_manager(cb, AsyncMock())
        self.assertEqual(p.create_hetzner_primary_ip.await_count, 2)
        self.assertIn('192.0.2.2', cb.message.edit_text.call_args.args[0])
        self.assertIn('quota', cb.message.edit_text.call_args.args[0])

    async def test_expired_confirmation_never_mutates(self):
        cb = self.cb('hp:ok:1:old')
        self.b.primary_confirmations['old'] = (0, 123, 4, 1, 'delete', ['2'])
        p = SimpleNamespace(delete_hetzner_primary_ip=AsyncMock())
        with patch.object(self.b.st, 'account', return_value={'id': 1, 'provider': 'hetzner'}), \
             patch.object(self.b.providers, 'Provider', return_value=p):
            await self.b.primary_manager(cb, AsyncMock())
        p.delete_hetzner_primary_ip.assert_not_awaited()
