import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import control_service
from store import Store


class ScopedRefreshTests(unittest.IsolatedAsyncioTestCase):
    def test_only_explicit_suspension_promotes_server_state(self):
        from providers import account_suspension
        for state in ['suspended', 'SUSPENDED', 'suspended/off', 'billing_suspension']:
            self.assertEqual(account_suspension([{'status': state}])['status'], 'suspended')
        for state in ['off', 'offline', 'stopped', 'halted', 'error', 'running', None]:
            self.assertEqual(account_suspension([{'status': state}], {'owed': 50}), {})
        self.assertEqual(account_suspension([], {'owed': 50}), {})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name + '/db', key_path=self.tmp.name + '/key')
        self.ids = [self.store.add_account(name, provider, 'dummy') for name, provider in
                    [('H1', 'hetzner'), ('H2', 'hetzner'), ('V1', 'vultr')]]
        self.visited = []

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def provider(self, account):
        self.visited.append(account['id'])
        p = AsyncMock()
        p.list_servers.return_value = [{'id': f"new-{account['id']}", 'label': 'New'}]
        p.hetzner_floating_ips.return_value = []
        p.vultr_reserved_ips.return_value = []
        p.account_info.return_value = {}
        p.whoami.return_value = 'owner'
        return p

    async def test_missing_snapshots_do_not_fetch_when_cached_only(self):
        with patch.object(control_service, 'Provider', side_effect=self.provider):
            for operation, field in [('all_servers', 'servers'), ('all_floating_ips', 'floating_ips'),
                                     ('check_all_accounts', 'accounts')]:
                result = await control_service.execute(operation, {'cached_only': True}, self.store)
                self.assertEqual(result[field], [])
                self.assertFalse(result.get('account_errors'))
        self.assertEqual(self.visited, [], 'Opening an empty dashboard must not contact cloud accounts')
        with patch.object(control_service, 'Provider', side_effect=self.provider):
            self.assertEqual(await control_service.execute('hetzner_primary_ips', {'cached_only': True, 'account_id': self.ids[0]}, self.store), {'primary_ips': []})
            self.assertEqual((await control_service.execute('dns_zones', {'cached_only': True}, self.store))['zones'], [])
        self.assertEqual(self.visited, [])

    async def test_suspension_survives_cached_checks_and_clears_on_recovery(self):
        p = self.provider(self.store.account(self.ids[0]))
        p.account_info.return_value = {'owed': 15, 'balance': 15}
        p.list_servers.return_value = [{'id': '1', 'status': 'billing_suspension'},
                                       {'id': '2', 'status': 'running'}]
        args = {'account_id': self.ids[0], 'refresh': True}
        with patch.object(control_service, 'Provider', return_value=p):
            result = await control_service.execute('check_all_accounts', args, self.store)
            item = result['accounts'][0]
            self.assertEqual(item['status'], 'suspended')
            self.assertEqual(item['info']['owed'], 15)
            self.assertIn('billing', item['error'])
            cached = await control_service.execute('check_all_accounts',
                {'account_id': self.ids[0], 'cached_only': True}, self.store)
            self.assertEqual(cached['accounts'][0]['status'], 'suspended')
            single = await control_service.execute('test_account', args, self.store)
            self.assertEqual(single['status'], 'suspended')
            p.list_servers.return_value = [{'id': '1', 'status': 'off'}]
            recovered = await control_service.execute('check_all_accounts', args, self.store)
            self.assertEqual(recovered['accounts'][0]['status'], 'ok')
            self.assertNotIn('error', recovered['accounts'][0])

    async def test_failed_inventory_check_does_not_claim_healthy(self):
        p = self.provider(self.store.account(self.ids[0]))
        p.list_servers.side_effect = RuntimeError('HTTP 403: insufficient permissions')
        with patch.object(control_service, 'Provider', return_value=p):
            result = await control_service.execute('check_all_accounts',
                {'account_id': self.ids[0], 'refresh': True}, self.store)
        self.assertEqual(result['accounts'][0]['status'], 'error')

    async def test_invalidation_retains_saved_snapshot_without_fetching(self):
        self.store.set_cache('all_servers', {'servers': [
            {'id': f'old-{i}', 'account_id': i} for i in self.ids], 'account_errors': {}})
        control_service._delete_cache(self.store, 'all_servers')
        self.assertIsNone(self.store.get_cache('all_servers'))
        with patch.object(control_service, 'Provider', side_effect=self.provider):
            result = await control_service.execute('all_servers', {'cached_only': True}, self.store)
        self.assertEqual(len(result['servers']), 3)
        self.assertEqual(self.visited, [])

    async def test_failed_scoped_refresh_keeps_saved_rows(self):
        self.store.set_cache('all_servers', {'servers': [
            {'id': f'old-{i}', 'account_id': i} for i in self.ids], 'account_errors': {}})
        p = AsyncMock()
        p.list_servers.side_effect = RuntimeError('temporary API error')
        with patch.object(control_service, 'Provider', return_value=p):
            result = await control_service.execute('all_servers', {'refresh': True, 'account_id': self.ids[1]}, self.store)
        self.assertEqual(result['servers'][0]['id'], 'old-2')
        self.assertIn('2', result['account_errors'])
        self.assertEqual(len(self.store.get_cache('all_servers')['servers']), 3)

    async def test_provider_refresh_preserves_other_providers(self):
        self.store.set_cache('all_servers', {'servers': [
            {'id': f'old-{i}', 'account_id': i} for i in self.ids], 'account_errors': {}})
        with patch.object(control_service, 'Provider', side_effect=self.provider):
            result = await control_service.execute('all_servers', {'refresh': True, 'provider': 'hetzner'}, self.store)
        self.assertEqual(self.visited, self.ids[:2])
        self.assertEqual({s['account_id'] for s in result['servers']}, set(self.ids[:2]))
        saved = self.store.get_cache('all_servers')['servers']
        self.assertEqual({s['id'] for s in saved}, {'new-1', 'new-2', 'old-3'})

    async def test_account_refresh_is_scoped_for_every_resource(self):
        for operation in ['all_servers', 'all_floating_ips', 'check_all_accounts']:
            self.visited.clear()
            with patch.object(control_service, 'Provider', side_effect=self.provider):
                await control_service.execute(operation, {'refresh': True, 'account_id': self.ids[1]}, self.store)
            self.assertEqual(self.visited, [self.ids[1]], operation)

    async def test_cached_scope_filters_rows_without_live_reads(self):
        self.store.set_cache('all_servers', {'servers': [
            {'id': f'old-{i}', 'account_id': i} for i in self.ids], 'account_errors': {'3': 'saved error'}})
        with patch.object(control_service, 'Provider', side_effect=self.provider):
            result = await control_service.execute('all_servers', {'cached_only': True, 'provider': 'hetzner'}, self.store)
        self.assertEqual({s['account_id'] for s in result['servers']}, set(self.ids[:2]))
        self.assertEqual(result['account_errors'], {})
        self.assertEqual(self.visited, [])
