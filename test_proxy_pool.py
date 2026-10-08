import asyncio
import importlib
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from aiogram import Dispatcher
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import InlineKeyboardButton

from proxy_pool import (ProxyPoolError, components, import_format, proxy_string,
                        resolve_country, session_ids)
from proxy_ui import Pool, register_proxy_ui
from store import Store


NICE = 'nice.example:17521:login-country-SG-ssid-AbC001-sst-15:test-password'
SWIFT = 'eu.swift.example:7878:login_custom_zone_SK_sid_000123_time_10:test-password'


class FormatTests(unittest.TestCase):
    def test_import_nice_numbering_and_deduplication(self):
        p, ids = import_format(NICE + '\n2\n' + NICE.replace('AbC001', 'Other002') + '\n3\n' + NICE)
        self.assertEqual(ids, ['AbC001', 'Other002'])
        self.assertEqual(p['username'], 'login-country-{country}-ssid-{session}-sst-15')

    def test_import_swift_mixed_countries(self):
        p, ids = import_format(SWIFT + '\n' + SWIFT.replace('_SK_', '_US_').replace('000123', '000456'))
        self.assertEqual(ids, ['000123', '000456'])
        self.assertEqual(p['username'], 'login_custom_zone_{country}_sid_{session}_time_10')

    def test_explicit_format_and_numeric_ids(self):
        p, ids = import_format('socks5://host.example:99:u_{country}_{session}:p\n2\n3\n0002\n2')
        self.assertEqual(ids, ['2', '3', '0002'])
        self.assertEqual(p['scheme'], 'socks5')
        self.assertEqual(import_format(proxy_string(p))[0], p)

    def test_credentials_encoding_and_ipv6(self):
        p = components('[2001:db8::1]:8080:a/b:p:with:colons')
        self.assertEqual(components(proxy_string(p)), p)
        special = components('host.example:80:user:p@ss:/?#%')
        self.assertEqual(special['password'], 'p@ss:/?#%')
        self.assertEqual(components(proxy_string(special)), special)

    def test_mixed_credentials_and_bad_placeholder_rejected(self):
        for text in (NICE+'\n'+NICE.replace('test-password', 'different'),
                     NICE+'\n'+SWIFT, 'h:80:u_{country}:p', 'h:80:u_{country}_{session}_{unknown}:p'):
            with self.subTest(text=text):
                with self.assertRaises(ProxyPoolError):
                    import_format(text)

    def test_country_lookup_and_invalid_input(self):
        for text, code in [('Germany', 'DE'), ('de', 'DE'), ('USA', 'US'), ('Singapore', 'SG'),
                           ('Slovakia', 'SK'), ('آلمان', 'DE'), ('آمریکا', 'US'), ('UK', 'GB')]:
            self.assertEqual(resolve_country(text), code)
        for value in ('ZZ', 'Atlantis', '', 'Frankfurt'):
            with self.assertRaises(ProxyPoolError):
                resolve_country(value)


class PoolStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db, self.key = self.tmp.name+'/db', self.tmp.name+'/key'
        self.st = Store(self.db, self.key)
        template, ids = import_format(NICE)
        self.pid = self.st.add_proxy_provider('Nice', template, ['AbC001', 'Other002'])
        self.a = self.st.add_account('one', 'vultr', 'token-one')
        self.b = self.st.add_account('two', 'linode', 'token-two')

    def tearDown(self):
        self.st.close()
        self.tmp.cleanup()

    def bind(self, account, country='DE', pid=None, another=False):
        r = self.st.allocate_proxy(pid or self.pid, country, account, another)
        self.st.set_proxy(account, r['proxy'], r['family'], proxy_request=r['token'])
        return r

    def test_two_accounts_same_country_get_different_sessions(self):
        first, second = self.bind(self.a), self.bind(self.b)
        self.assertNotEqual(first['session_id'], second['session_id'])
        self.assertEqual(self.st.proxy_availability(self.pid, 'DE'), 0)

    def test_superseding_current_reservation_preserves_bound_claim(self):
        bound = self.bind(self.a)
        template, _ = import_format(SWIFT)
        other = self.st.add_proxy_provider('Swift', template, ['00001'])
        for method in ('reserve', 'allocate'):
            for pid in (self.pid, other):
                with self.subTest(method=method, provider=pid):
                    current = self.st.reserve_proxy(bound['proxy'], self.a)
                    if method == 'allocate':
                        candidate = self.st.allocate_proxy(pid, 'US', self.a)
                    else:
                        candidate = self.st.allocate_proxy(pid, 'US')
                        self.st.release_proxy_reservation(candidate['token'])
                        candidate = self.st.reserve_proxy(candidate['proxy'], self.a)
                    with self.assertRaises(ProxyPoolError):
                        self.st.set_proxy(self.a, bound['proxy'], proxy_request=current['token'])
                    with self.assertRaises(ProxyPoolError):
                        self.st.manage_proxy_session(self.pid, bound['session_id'], 'delete')
                    for action in ('delete', 'format'):
                        with self.assertRaises(ProxyPoolError):
                            self.st.manage_proxy_provider(self.pid, action, template)
                    self.assertEqual(self.st.account(self.a)['proxy'], bound['proxy'])
                    self.st.set_proxy(self.a, candidate['proxy'], proxy_request=candidate['token'])
                    self.bind(self.a, 'DE', self.pid)

    def test_session_is_independent_between_countries_and_providers(self):
        first, second = self.bind(self.a), self.bind(self.b, 'US')
        self.assertEqual(first['session_id'], second['session_id'])
        t, _ = import_format(SWIFT)
        other = self.st.add_proxy_provider('Swift', t, ['AbC001'])
        third = self.st.add_account('three', 'hetzner', 'token-three')
        self.assertEqual(self.bind(third, pid=other)['session_id'], first['session_id'])

    def test_manual_copy_and_changed_password_or_scheme_cannot_bypass(self):
        r = self.bind(self.a)
        p = components(r['proxy'])
        p.update(password='different', scheme='socks5')
        for candidate in (r['proxy'], proxy_string(p), r['proxy'].replace('country-DE', 'country-de'),
                          r['proxy'].replace('sst-15', 'sst-30')):
            with self.assertRaises(ProxyPoolError):
                self.st.set_proxy(self.b, candidate)
            with self.assertRaises(ProxyPoolError):
                self.st.add_account('copy', 'vultr', 'token', candidate)

    def test_duplicate_provider_template_cannot_bypass(self):
        t, _ = import_format(NICE)
        t.update(password='changed', scheme='socks5')
        with self.assertRaises(ProxyPoolError):
            self.st.add_proxy_provider('Alias', t, ['AbC001'])
        t['username'] = t['username'].replace('sst-15', 'sst-30')
        with self.assertRaises(ProxyPoolError):
            self.st.add_proxy_provider('Alias duration', t, ['AbC001'])

    def test_country_change_keeps_session_or_uses_next_free(self):
        first = self.bind(self.a)
        self.bind(self.b, 'US')
        moved = self.bind(self.a, 'US')
        self.assertNotEqual(first['session_id'], moved['session_id'])
        moved_again = self.bind(self.a, 'SG')
        self.assertEqual(moved['session_id'], moved_again['session_id'])

    def test_idempotent_and_another_session(self):
        first = self.bind(self.a)
        self.assertEqual(self.bind(self.a)['session_id'], first['session_id'])
        self.assertNotEqual(self.bind(self.a, another=True)['session_id'], first['session_id'])

    def test_remove_replace_and_delete_release_identity(self):
        first = self.bind(self.a)
        self.st.set_proxy(self.a, None)
        self.assertEqual(self.bind(self.b)['session_id'], first['session_id'])
        self.st.delete_account(self.b)
        self.assertEqual(self.bind(self.a)['session_id'], first['session_id'])
        self.bind(self.a, another=True)
        new = self.st.add_account('new', 'vultr', 'token')
        self.assertEqual(self.bind(new)['session_id'], first['session_id'])

    def test_reservation_cancel_and_expiry(self):
        r = self.st.allocate_proxy(self.pid, 'DE', self.a)
        self.st.release_proxy_reservation(r['token'])
        with self.assertRaises(ProxyPoolError):
            self.st.set_proxy(self.a, r['proxy'], proxy_request=r['token'])
        r = self.st.allocate_proxy(self.pid, 'DE', self.a)
        self.st.con.execute('UPDATE proxy_claims SET expires_at=0 WHERE request_token=?', (r['token'],))
        self.st.con.commit()
        with self.assertRaises(ProxyPoolError):
            self.st.set_proxy(self.a, r['proxy'], proxy_request=r['token'])
        self.assertIsNone(self.st.account(self.a)['proxy'])
        self.assertEqual(self.st.proxy_availability(self.pid, 'DE'), 2)

    def test_stale_request_cannot_overwrite_new_binding(self):
        old = self.st.allocate_proxy(self.pid, 'DE', self.a)
        new = self.bind(self.a, 'US')
        with self.assertRaises(ProxyPoolError):
            self.st.set_proxy(self.a, old['proxy'], proxy_request=old['token'])
        self.assertEqual(self.st.account(self.a)['proxy'], new['proxy'])

    def test_only_reserved_account_can_commit(self):
        r = self.st.allocate_proxy(self.pid, 'DE', self.a)
        with self.assertRaises(ProxyPoolError):
            self.st.set_proxy(self.b, r['proxy'], proxy_request=r['token'])

    def test_bound_claim_survives_cancel_expiry_and_second_store(self):
        r = self.bind(self.a)
        pending = self.st.allocate_proxy(self.pid, 'DE', self.a)
        second = Store(self.db, self.key)
        try:
            self.st.set_proxy(self.a, pending['proxy'], proxy_request=pending['token'])
            pending = self.st.allocate_proxy(self.pid, 'DE', self.a)
            self.st.release_proxy_reservation(pending['token'])
            with self.assertRaises(ProxyPoolError):
                second.set_proxy(self.b, r['proxy'])
        finally:
            second.close()

    def test_unused_entries_manageable_bound_entries_protected(self):
        self.bind(self.a)
        with self.assertRaises(ProxyPoolError):
            self.st.manage_proxy_provider(self.pid, 'delete')
        with self.assertRaises(ProxyPoolError):
            self.st.manage_proxy_session(self.pid, 'AbC001', 'delete')
        self.st.manage_proxy_session(self.pid, 'Other002', 'delete')
        self.st.manage_proxy_provider(self.pid, 'rename', 'Renamed')
        self.assertEqual(self.st.proxy_provider(self.pid)['label'], 'Renamed')

    def test_format_edit_requires_unused_provider(self):
        template, _ = import_format(NICE.replace('login-', 'new-login-'))
        self.st.manage_proxy_provider(self.pid, 'format', template)
        self.assertEqual(self.st.proxy_provider(self.pid)['template'], template)
        self.bind(self.a)
        with self.assertRaises(ProxyPoolError):
            self.st.manage_proxy_provider(self.pid, 'format', template)

    def test_disabled_current_session_remains_idempotent(self):
        first = self.bind(self.a)
        self.st.manage_proxy_session(self.pid, first['session_id'], 'toggle')
        self.assertEqual(self.bind(self.a)['session_id'], first['session_id'])
        self.assertNotEqual(self.bind(self.a, 'US')['session_id'], first['session_id'])

    def test_disable_preserves_binding_and_cancels_validation(self):
        first = self.bind(self.a)
        pending = self.st.allocate_proxy(self.pid, 'US', self.b)
        self.st.manage_proxy_session(self.pid, 'AbC001', 'toggle')
        with self.assertRaises(ProxyPoolError):
            self.st.set_proxy(self.b, pending['proxy'], proxy_request=pending['token'])
        self.assertEqual(self.st.account(self.a)['proxy'], first['proxy'])
        self.assertEqual(self.bind(self.b)['session_id'], 'Other002')

    def test_disabled_provider_cannot_assign_or_be_deleted_while_bound(self):
        self.bind(self.a)
        self.st.allocate_proxy(self.pid, 'DE', self.a)
        self.st.manage_proxy_provider(self.pid, 'toggle')
        with self.assertRaises(ProxyPoolError):
            self.st.allocate_proxy(self.pid, 'US', self.b)
        with self.assertRaises(ProxyPoolError):
            self.st.manage_proxy_provider(self.pid, 'delete')

    def test_restart_binding_and_pending_validation_persist(self):
        first = self.bind(self.a)
        pending = self.st.allocate_proxy(self.pid, 'US', self.b)
        self.st.close()
        self.st = Store(self.db, self.key)
        self.assertEqual(self.st.account(self.a)['proxy'], first['proxy'])
        self.st.set_proxy(self.b, pending['proxy'], proxy_request=pending['token'])
        self.assertEqual(self.st.proxy_binding(self.b)['country'], 'US')

    def test_new_account_commits_reservation_atomically(self):
        r = self.st.allocate_proxy(self.pid, 'DE')
        account = self.st.add_account('new', 'vultr', 'token', r['proxy'], proxy_request=r['token'])
        self.assertEqual(self.st.proxy_binding(account)['session_id'], r['session_id'])
        with self.assertRaises(ProxyPoolError):
            self.st.add_account('again', 'vultr', 'token', r['proxy'], proxy_request=r['token'])

    def test_last_pair_concurrent_connections_have_one_winner(self):
        self.bind(self.a)
        barrier = threading.Barrier(2)

        def request():
            st = Store(self.db, self.key)
            try:
                barrier.wait(timeout=5)
                try:
                    return st.allocate_proxy(self.pid, 'DE')['token']
                except ProxyPoolError:
                    return None
            finally:
                st.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: request(), range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)

    def test_credentials_encrypted_and_not_in_plain_indexes(self):
        row = self.st.con.execute('SELECT template,identity FROM proxy_providers').fetchone()
        self.assertNotIn(b'test-password', row['template'])
        self.assertNotIn('login', row['identity'])
        r = self.st.allocate_proxy(self.pid, 'DE', self.a)
        raw = self.st.con.execute('SELECT proxy FROM proxy_claims WHERE request_token=?', (r['token'],)).fetchone()[0]
        self.assertNotIn(b'test-password', raw)

    def test_legacy_duplicates_flagged_without_modifying_proxies(self):
        # Simulate a pre-feature database; direct SQL is restricted to fixture setup.
        encrypted = self.st.f.encrypt(NICE.encode())
        self.st.con.execute('UPDATE accounts SET proxy=?', (encrypted,))
        self.st.con.commit()
        self.st.close()
        self.st = Store(self.db, self.key)
        self.assertEqual(len(self.st.proxy_conflicts()), 1)
        self.assertEqual(self.st.account(self.a)['proxy'], NICE)
        r = self.bind(self.a, 'SG')
        self.assertEqual(r['session_id'], 'Other002')
        self.assertEqual(self.st.proxy_conflicts(), [])
        with self.assertRaises(ProxyPoolError):
            self.st.set_proxy(self.a, NICE)


class PoolUITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.st = Store(self.tmp.name+'/db', self.tmp.name+'/key')
        t, ids = import_format(NICE)
        self.pid = self.st.add_proxy_provider('Nice', t, ['AbC001', 'Other002'])
        self.account = self.st.add_account('account', 'vultr', 'test-token')
        self.storage = MemoryStorage()
        self.state = FSMContext(storage=self.storage, key=StorageKey(bot_id=1, chat_id=1, user_id=123))
        self.client = SimpleNamespace(whoami=AsyncMock(return_value='owner'))
        self.progress = SimpleNamespace(edit_text=AsyncMock())
        self.provider = unittest.mock.Mock(return_value=self.client)

        async def clear(state):
            data = await state.get_data()
            if data.get('proxy_request'):
                self.st.release_proxy_reservation(data['proxy_request'])
            await state.clear()

        self.host = {'st': self.st, 'OWNER': 123, 'clear_proxy_state': clear,
                     'providers': SimpleNamespace(Provider=self.provider),
                     'menu_cache': SimpleNamespace(invalidate=unittest.mock.Mock()),
                     'kb_account_settings': lambda a: None, 'edit_menu_message': AsyncMock(),
                     'InlineKeyboardButton': InlineKeyboardButton,
                     '_proxy_failure_hint': lambda e: '\nIP not allowed' if 'Unauthorized IP address' in str(e) else '',
                     'safe_proxy_error': lambda e, p, t: str(e),
                     'Add': SimpleNamespace(proxy=Pool.format), 'Proxy': SimpleNamespace(value=Pool.ids),
                     'kb_proxy_choice': lambda target: None}
        self.dp = Dispatcher()
        register_proxy_ui(self.dp, self.host)
        self.callbacks = {h.callback.__name__: h.callback for h in self.dp.callback_query.handlers}
        self.messages = {h.callback.__name__: h.callback for h in self.dp.message.handlers}

    async def asyncTearDown(self):
        self.st.close()
        await self.storage.close()
        self.tmp.cleanup()

    def cb(self, data, owner=123):
        return SimpleNamespace(data=data, from_user=SimpleNamespace(id=owner),
                               message=self.progress, answer=AsyncMock())

    async def enter_country(self, country='Germany'):
        await self.state.update_data(pool_target=str(self.account), pool_provider_id=self.pid)
        await self.state.set_state(Pool.country)
        msg = SimpleNamespace(text=country, from_user=SimpleNamespace(id=123), answer=AsyncMock(return_value=self.progress))
        await self.messages['country_input'](msg, self.state)

    async def test_account_assignment_and_country_only_start(self):
        await self.callbacks['assign_start'](self.cb(f'pooluse:{self.account}'), self.state)
        self.assertEqual((await self.state.get_data())['pool_provider_id'], self.pid)
        await self.enter_country()
        self.assertEqual(self.st.proxy_binding(self.account)['country'], 'DE')
        self.assertIsNone(await self.state.get_state())

    async def test_failed_validation_keeps_old_proxy_and_releases_candidate(self):
        old = 'unrelated.example:80:old:password'
        self.st.set_proxy(self.account, old)
        self.client.whoami.side_effect = RuntimeError('unreachable')
        await self.enter_country()
        self.assertEqual(self.st.account(self.account)['proxy'], old)
        self.assertEqual(self.st.proxy_availability(self.pid, 'DE'), 2)
        self.assertEqual(await self.state.get_state(), Pool.validation.state)

    async def test_unverified_save_still_cannot_take_another_accounts_proxy(self):
        self.client.whoami.side_effect = RuntimeError('HTTP 401 Unauthorized IP address')
        await self.enter_country()
        data = await self.state.get_data()
        other = self.st.add_account('other', 'vultr', 'other-token', data['proxy'])
        await self.callbacks['unverified'](self.cb('poolunverified'), self.state)
        self.assertIsNone(self.st.account(self.account)['proxy'])
        self.assertEqual(self.st.account(other)['proxy'], data['proxy'])

    async def test_unverified_save_allowed_after_vultr_access_failure(self):
        self.client.whoami.side_effect = RuntimeError('HTTP 401 Unauthorized IP address')
        await self.enter_country()
        await self.callbacks['unverified'](self.cb('poolunverified'), self.state)
        self.assertEqual(self.st.proxy_binding(self.account)['country'], 'DE')

    async def test_cancel_inflight_validation_never_saves(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def whoami():
            entered.set()
            await release.wait()

        self.client.whoami.side_effect = whoami
        task = asyncio.create_task(self.enter_country())
        await entered.wait()
        await self.host['clear_proxy_state'](self.state)
        release.set()
        await task
        self.assertIsNone(self.st.account(self.account)['proxy'])
        self.assertEqual(self.st.proxy_availability(self.pid, 'DE'), 2)

    async def test_provider_switch_cancels_inflight_validation(self):
        template, _ = import_format(SWIFT)
        other = self.st.add_proxy_provider('Swift', template, ['00001'])
        for target in (str(self.account), 'new'):
            for fails in (False, True):
                with self.subTest(target=target, fails=fails):
                    await self.state.clear()
                    await self.state.update_data(pool_target=target, pool_provider_id=self.pid,
                                                 label='new', provider='linode', token='new-token')
                    entered, release = asyncio.Event(), asyncio.Event()

                    async def whoami():
                        entered.set()
                        await release.wait()
                        if fails:
                            raise RuntimeError('unreachable')

                    self.client.whoami.side_effect = whoami
                    msg = SimpleNamespace(text='DE', from_user=SimpleNamespace(id=123),
                                          answer=AsyncMock(return_value=self.progress))
                    task = asyncio.create_task(self.messages['country_input'](msg, self.state))
                    await entered.wait()
                    await self.callbacks['choose_provider'](self.cb(f'poolprovider:{target}:{other}'), self.state)
                    available = self.st.proxy_availability(self.pid, 'DE')
                    wizard = await self.state.get_data()
                    calls = self.progress.edit_text.call_count
                    release.set()
                    await task
                    self.assertEqual(available, 2)
                    self.assertEqual(await self.state.get_state(), Pool.country.state)
                    self.assertEqual(await self.state.get_data(), wizard)
                    self.assertEqual(wizard['pool_provider_id'], other)
                    self.assertEqual(self.progress.edit_text.call_count, calls)
                    self.assertEqual(len(self.st.accounts()), 1)
                    self.assertIsNone(self.st.account(self.account)['proxy'])

    async def test_new_account_wizard_uses_pool(self):
        await self.state.update_data(pool_target='new', pool_provider_id=self.pid,
                                     label='new', provider='linode', token='new-token')
        await self.state.set_state(Pool.country)
        msg = SimpleNamespace(text='US', from_user=SimpleNamespace(id=123), answer=AsyncMock(return_value=self.progress))
        await self.messages['country_input'](msg, self.state)
        account = self.st.accounts()[-1]
        self.assertEqual(account['label'], 'new')
        self.assertEqual(self.st.proxy_binding(account['id'])['country'], 'US')

    async def test_stale_provider_callback_does_not_overwrite_wizard(self):
        await self.state.update_data(pool_target=str(self.account))
        await self.callbacks['choose_provider'](self.cb(f'poolprovider:new:{self.pid}'), self.state)
        self.assertEqual((await self.state.get_data())['pool_target'], str(self.account))

    async def test_owner_only_provider_mutations(self):
        await self.callbacks['provider_action'](self.cb(f'pp:{self.pid}:delete', owner=999), self.state)
        self.assertIsNotNone(self.st.proxy_provider(self.pid))

    async def test_stale_deleted_session_button_does_not_change_new_id(self):
        old_id = self.st.proxy_sessions(self.pid)[-1]['id']
        self.st.manage_proxy_session(self.pid, 'Other002', 'delete')
        self.st.add_proxy_sessions(self.pid, ['BrandNew'])
        await self.callbacks['session_action'](self.cb(f'ps:{self.pid}:{old_id}:toggle:0'), self.state)
        self.assertTrue(self.st.proxy_sessions(self.pid)[-1]['enabled'])

    async def test_full_lines_provider_wizard(self):
        await self.state.set_state(Pool.format)
        await self.state.update_data(pool_label='Swift')
        msg = SimpleNamespace(text=SWIFT, from_user=SimpleNamespace(id=123), delete=AsyncMock(), answer=AsyncMock())
        await self.messages['format_input'](msg, self.state)
        msg.delete.assert_awaited_once()
        self.assertIsNone(await self.state.get_state())
        provider = self.st.proxy_providers()[-1]
        self.assertEqual(provider['label'], 'Swift')
        self.assertEqual(provider['family'], 'default')
        self.assertEqual(self.st.proxy_sessions(provider['id'])[0]['session_id'], '000123')

    async def test_generic_provider_added_during_new_account_import(self):
        await self.state.update_data(pool_target='new', label='new', provider='linode', token='new-token')
        await self.callbacks['add_start'](self.cb('pooladd:new'), self.state)
        msg = SimpleNamespace(text='Any provider', from_user=SimpleNamespace(id=123), answer=AsyncMock())
        await self.messages['label'](msg, self.state)
        msg.text = 'generic.example:8080:account-{country}-sid-{session_id}:password'
        msg.delete = AsyncMock()
        await self.messages['format_input'](msg, self.state)
        self.assertEqual(await self.state.get_state(), Pool.ids.state)
        msg.text = '001\n002\n001'
        await self.messages['ids_input'](msg, self.state)
        data = await self.state.get_data()
        self.assertEqual(await self.state.get_state(), Pool.country.state)
        self.assertEqual(data['token'], 'new-token')
        self.assertEqual(data['label'], 'new')
        self.assertEqual(len(self.st.proxy_sessions(data['pool_provider_id'])), 2)
        msg.text = 'DE'
        msg.answer = AsyncMock(return_value=self.progress)
        await self.messages['country_input'](msg, self.state)
        account = self.st.accounts()[-1]
        self.assertEqual(components(account['proxy'])['username'], 'account-DE-sid-001')
        self.assertEqual(account['proxy_family'], 'default')

    async def test_country_and_failure_screens_allow_custom(self):
        await self.callbacks['assign_start'](self.cb(f'pooluse:{self.account}'), self.state)
        markup = self.progress.edit_text.call_args.kwargs['reply_markup']
        self.assertIn(f'poolcustom:{self.account}', [b.callback_data for row in markup.inline_keyboard for b in row])
        self.client.whoami.side_effect = RuntimeError('unreachable')
        await self.enter_country()
        candidate = (await self.state.get_data())['proxy']
        await self.callbacks['manual'](self.cb(f'poolcustom:{self.account}'), self.state)
        self.assertEqual((await self.state.get_data())['acc_id'], self.account)
        self.assertIsNone(self.st.account(self.account)['proxy'])
        self.assertEqual(self.st.proxy_availability(self.pid, 'DE'), 2)
        self.assertEqual(await self.state.get_state(), Pool.ids.state)

    async def test_empty_provider_list_offers_add_and_custom(self):
        self.st.manage_proxy_provider(self.pid, 'delete')
        await self.callbacks['assign_start'](self.cb(f'poolpick:{self.account}'), self.state)
        markup = self.progress.edit_text.call_args.kwargs['reply_markup']
        buttons = [b.callback_data for row in markup.inline_keyboard for b in row]
        self.assertIn(f'pooladd:{self.account}', buttons)
        self.assertIn(f'poolcustom:{self.account}', buttons)

    async def test_new_custom_switch_keeps_credentials_and_releases_reservation(self):
        r = self.st.allocate_proxy(self.pid, 'DE')
        await self.state.update_data(pool_target='new', label='new', token='new-token', provider='linode', proxy_request=r['token'])
        await self.callbacks['manual'](self.cb('poolcustom:new'), self.state)
        self.assertEqual((await self.state.get_data())['token'], 'new-token')
        self.assertIsNone((await self.state.get_data())['proxy_request'])
        self.assertEqual(self.st.proxy_availability(self.pid, 'DE'), 2)


class ExistingProxyBotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            'CLOUDBOT_TOKEN': '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi',
            'CLOUDBOT_OWNER': '123', 'CLOUDBOT_DB': self.tmp.name+'/db',
            'CLOUDBOT_KEY': self.tmp.name+'/key'})
        self.env.start()
        self.bot = importlib.import_module('bot')
        self.st = Store(self.tmp.name+'/db', self.tmp.name+'/key')
        self.store_patch = patch.object(self.bot, 'st', self.st)
        self.store_patch.start()
        t, _ = import_format(NICE)
        self.pid = self.st.add_proxy_provider('Nice', t, ['AbC001', 'Other002'])
        self.a = self.st.add_account('one', 'vultr', 'token-one')
        self.b = self.st.add_account('two', 'vultr', 'token-two')
        self.state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=1, user_id=123))
        self.message = SimpleNamespace(edit_text=AsyncMock())

    async def asyncTearDown(self):
        self.store_patch.stop()
        self.env.stop()
        self.st.close()
        self.tmp.cleanup()

    async def test_manual_duplicate_rejected_before_api_request(self):
        self.st.set_proxy(self.a, NICE)
        await self.state.set_state(self.bot.Proxy.family)
        await self.state.update_data(acc_id=self.b, proxy=NICE)
        with patch.object(self.bot.providers, 'Provider') as provider:
            result = await self.bot._validate_and_save_proxy(self.message, self.state, NICE, 'default', 'account')
        provider.assert_not_called()
        self.assertFalse(result)
        self.assertIsNone(self.st.account(self.b)['proxy'])

    async def test_manual_failure_redacts_credentials_and_releases(self):
        await self.state.set_state(self.bot.Proxy.family)
        await self.state.update_data(acc_id=self.a, proxy=NICE)
        client = SimpleNamespace(whoami=AsyncMock(side_effect=RuntimeError('failed test-password token-one')))
        with patch.object(self.bot.providers, 'Provider', return_value=client):
            await self.bot._validate_and_save_proxy(self.message, self.state, NICE, 'default', 'account')
        text = self.message.edit_text.call_args.args[0]
        self.assertNotIn('test-password', text)
        self.assertNotIn('token-one', text)
        self.assertEqual(self.st.proxy_availability(self.pid, 'SG'), 2)

    async def test_manual_cancel_does_not_clear_new_request(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def whoami():
            entered.set()
            await release.wait()

        await self.state.set_state(self.bot.Proxy.family)
        await self.state.update_data(acc_id=self.a, proxy=NICE)
        with patch.object(self.bot.providers, 'Provider', return_value=SimpleNamespace(whoami=whoami)):
            task = asyncio.create_task(self.bot._validate_and_save_proxy(self.message, self.state, NICE, 'default', 'account'))
            await entered.wait()
            await self.bot.clear_proxy_state(self.state)
            new = self.st.allocate_proxy(self.pid, 'US', self.a)
            await self.state.set_state(self.bot.Proxy.family)
            await self.state.update_data(acc_id=self.a, proxy=new['proxy'], proxy_request=new['token'])
            release.set()
            self.assertFalse(await task)
        self.assertEqual((await self.state.get_data())['proxy_request'], new['token'])
        self.st.set_proxy(self.a, new['proxy'], proxy_request=new['token'])

    async def test_manual_unverified_save_cannot_duplicate(self):
        self.st.set_proxy(self.a, NICE)
        await self.state.set_state(self.bot.Proxy.family)
        await self.state.update_data(acc_id=self.b, proxy=NICE, proxy_allow_unverified=True)
        cb = SimpleNamespace(message=self.message, answer=AsyncMock())
        await self.bot.prx_save_unverified(cb, self.state)
        self.assertIsNone(self.st.account(self.b)['proxy'])

    async def test_manual_new_account_duplicate_rejected_before_api_request(self):
        self.st.set_proxy(self.a, NICE)
        with patch.object(self.bot.providers, 'Provider') as provider:
            result = await self.bot._finish_add({'label': 'duplicate', 'provider': 'vultr', 'token': 'new-token'},
                                               NICE, 'default', AsyncMock())
        self.assertFalse(result)
        provider.assert_not_called()
        self.assertEqual(len(self.st.accounts()), 2)

    async def test_custom_replacement_tests_immediately_with_default(self):
        await self.state.set_state(self.bot.Proxy.value)
        await self.state.update_data(acc_id=self.a)
        msg = SimpleNamespace(text=NICE, delete=AsyncMock(), answer=AsyncMock(return_value=self.message))
        client = SimpleNamespace(whoami=AsyncMock(return_value='owner'))
        with patch.object(self.bot.providers, 'Provider', return_value=client) as provider:
            await self.bot.prx_set(msg, self.state)
        self.assertEqual(provider.call_args.args[0]['proxy_family'], 'default')
        self.assertEqual(self.st.account(self.a)['proxy'], NICE)
        self.assertIsNone(await self.state.get_state())

    async def test_custom_new_account_tests_immediately_with_default(self):
        await self.state.set_state(self.bot.Add.proxy)
        await self.state.update_data(label='new', provider='linode', token='new-token')
        msg = SimpleNamespace(text=NICE, delete=AsyncMock(), answer=AsyncMock(return_value=self.message))
        client = SimpleNamespace(whoami=AsyncMock(return_value='owner'))
        with patch.object(self.bot.providers, 'Provider', return_value=client) as provider:
            await self.bot.add_proxy(msg, self.state)
        self.assertEqual(provider.call_args.args[0]['proxy_family'], 'default')
        self.assertEqual(self.st.accounts()[-1]['label'], 'new')
        self.assertIsNone(await self.state.get_state())

    async def test_old_ipv6_callback_uses_default(self):
        await self.state.set_state(self.bot.Proxy.family)
        await self.state.update_data(acc_id=self.a, proxy=NICE)
        client = SimpleNamespace(whoami=AsyncMock(return_value='owner'))
        cb = SimpleNamespace(data='prxfam:ipv6', message=self.message, answer=AsyncMock())
        with patch.object(self.bot.providers, 'Provider', return_value=client) as provider:
            await self.bot.prx_family(cb, self.state)
        self.assertEqual(provider.call_args.args[0]['proxy_family'], 'default')

    async def test_existing_preferences_migrate_without_changing_credentials(self):
        self.st.set_proxy(self.a, NICE)
        before = self.st.account(self.a)
        self.st.con.execute("UPDATE accounts SET proxy_family='ipv6' WHERE id=?", (self.a,))
        self.st.con.execute("UPDATE proxy_providers SET family='ipv4' WHERE id=?", (self.pid,))
        self.st.con.commit()
        migrated = Store(self.tmp.name+'/db', self.tmp.name+'/key')
        try:
            after = migrated.account(self.a)
            self.assertEqual(after['proxy'], before['proxy'])
            self.assertEqual(after['token'], before['token'])
            self.assertEqual(after['proxy_family'], 'default')
            self.assertEqual(after['proxy_revision'], before['proxy_revision']+1)
            self.assertEqual(migrated.proxy_provider(self.pid)['family'], 'default')
        finally:
            migrated.close()

    async def test_transport_url_handles_special_credentials(self):
        proxy = 'host.example:80:user:p@ss:/?#%'
        self.assertEqual(components(self.bot.providers.proxy_url(proxy))['password'], 'p@ss:/?#%')


if __name__ == '__main__':
    unittest.main()
