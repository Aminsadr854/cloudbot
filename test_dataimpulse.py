import asyncio
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestServer

import control_service
import providers
from proxy_pool import ProxyPoolError, components, import_format, proxy_string
from store import Store


SAMPLE = 'example-login__cr.de:example-password@gw.dataimpulse.com:10000'


class DataImpulseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db, self.key = self.tmp.name + '/db', self.tmp.name + '/key'
        self.store = Store(self.db, key_path=self.key)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_import_ports_and_roundtrip_template(self):
        template, ids = import_format('\n'.join(SAMPLE.replace('10000', str(p)) for p in range(10000, 10015)))
        self.assertEqual(ids, [str(p) for p in range(10000, 10015)])
        self.assertEqual(template['port'], '{port}')
        self.assertEqual(template['username'], 'example-login__cr.{country}')
        self.assertEqual(import_format(proxy_string(template))[0], template)

    def test_country_switch_and_port_collision(self):
        pid = self.store.add_proxy_provider('DataImpulse', SAMPLE, ['10000', '10001'])
        first = self.store.allocate_proxy(pid, 'Germany')
        self.assertEqual(components(first['proxy'])['port'], 10000)
        self.assertEqual(components(first['proxy'])['username'], 'example-login__cr.de')
        account = self.store.add_account('A', 'hetzner', 'dummy', first['proxy'], proxy_request=first['token'])
        second = self.store.allocate_proxy(pid, 'DE')
        self.assertEqual(components(second['proxy'])['port'], 10001)
        changed = self.store.allocate_proxy(pid, 'US', account)
        self.assertEqual(components(changed['proxy'])['port'], 10000)
        self.assertEqual(components(changed['proxy'])['username'], 'example-login__cr.us')
        self.store.set_proxy(account, changed['proxy'], proxy_request=changed['token'])
        self.assertEqual(self.store.proxy_binding(account)['session_id'], '10000')

    def test_bad_ports_and_mixed_passwords_rejected(self):
        for value in ('9999', '20001', 'session-one'):
            with self.subTest(value=value), self.assertRaises(ProxyPoolError):
                self.store.add_proxy_provider('Bad', SAMPLE, [value])
        with self.assertRaises(ProxyPoolError):
            import_format(SAMPLE + '\n' + SAMPLE.replace('example-password', 'other'))

    def test_default_limit_and_persistent_usage(self):
        from proxy_usage import ProxyUsage, TrafficLimitExceeded
        pid = self.store.add_proxy_provider('DataImpulse', SAMPLE, ['10000'])
        self.assertEqual(self.store.proxy_provider(pid)['usage_limit_bytes'], 100_000_000)
        meter = ProxyUsage(SAMPLE, self.db, self.key)
        meter.consume(123)
        self.assertEqual(self.store.proxy_provider(pid)['usage_bytes'], 123)
        other = ProxyUsage(SAMPLE.replace('__cr.de', '__cr.us'), self.db, self.key)
        other.consume(77)
        self.assertEqual(self.store.proxy_provider(pid)['usage_bytes'], 200)
        self.store.configure_proxy_usage(pid, limit_gb=0.0000002)
        with self.assertRaises(TrafficLimitExceeded):
            meter.ensure_available()
        self.store.configure_proxy_usage(pid, reset=True)
        self.assertEqual(self.store.proxy_provider(pid)['usage_bytes'], 0)
        for limit in (-1, float('nan'), float('inf'), 'bad'):
            with self.subTest(limit=limit), self.assertRaises(ProxyPoolError):
                self.store.configure_proxy_usage(pid, limit_gb=limit)

    def test_concurrent_charges_share_one_allowance(self):
        from proxy_usage import ProxyUsage, TrafficLimitExceeded
        pid = self.store.add_proxy_provider('DataImpulse', SAMPLE, ['10000'], usage_limit_gb=0.0000001)
        def charge(_):
            try:
                ProxyUsage(SAMPLE, self.db, self.key).consume(17)
                return True
            except TrafficLimitExceeded:
                return False
        with ThreadPoolExecutor(max_workers=6) as pool:
            successes = list(pool.map(charge, range(10)))
        self.assertEqual(sum(successes), 5)
        self.assertEqual(self.store.proxy_provider(pid)['usage_bytes'], 85)

    def test_duration_change_cannot_bypass_provider_budget(self):
        from proxy_usage import ProxyUsage
        pid = self.store.add_proxy_provider('DataImpulse', SAMPLE, ['10000'])
        ProxyUsage(SAMPLE.replace('__cr.de', '__cr.de;sessttl.60'), self.db, self.key).consume(33)
        self.assertEqual(self.store.proxy_provider(pid)['usage_bytes'], 33)


class MeteredRequestsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db, self.key = self.tmp.name + '/db', self.tmp.name + '/key'
        self.store = Store(self.db, key_path=self.key)
        self.env = patch.dict(os.environ, {'CLOUDBOT_DB': self.db, 'CLOUDBOT_KEY': self.key})
        self.env.start()
        self.calls = 0

        async def handler(request):
            self.calls += 1
            return web.json_response({'value': 'x' * 5000})

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', handler)
        self.server = TestServer(app)
        await self.server.start_server()
        port = self.server.port
        template = f'http://u-country-{{country}}-ssid-{{session}}-sst-15:p@127.0.0.1:{port}'
        self.pid = self.store.add_proxy_provider('Test pool', template, ['one'])
        self.proxy = f'http://u-country-DE-ssid-one-sst-15:p@127.0.0.1:{port}'
        self.provider = providers.Provider({'provider': 'hetzner', 'token': 'dummy', 'proxy': self.proxy})
        self.provider._base = lambda: 'http://example.invalid'

    async def asyncTearDown(self):
        await self.server.close()
        self.env.stop()
        self.store.close()
        self.tmp.cleanup()

    async def test_real_request_charges_traffic_and_exhaustion_stops_new_requests(self):
        result = await self.provider._req('GET', '/test')
        self.assertEqual(len(result['value']), 5000)
        used = self.store.proxy_provider(self.pid)['usage_bytes']
        self.assertGreater(used, 5000)
        self.store.configure_proxy_usage(self.pid, limit_gb=used / 1_000_000_000)
        before = self.calls
        with self.assertRaisesRegex(Exception, 'traffic limit reached') as error:
            await self.provider._req('GET', '/test')
        self.assertFalse(providers.is_proxy_failure(error.exception))
        self.assertEqual(self.calls, before)

    async def test_large_response_cannot_consume_past_allowance(self):
        self.store.configure_proxy_usage(self.pid, limit_gb=0.000001)
        with self.assertRaisesRegex(Exception, 'traffic limit reached'):
            await self.provider._req('GET', '/large')
        self.assertLessEqual(self.store.proxy_provider(self.pid)['usage_bytes'], 1000)

    async def test_api_import_and_limit_edit(self):
        result = await control_service.execute('add_proxy_provider', {
            'label': 'DataImpulse', 'template': SAMPLE + '\n' + SAMPLE.replace('10000', '10001'),
            'usage_limit_gb': 0.1,
        }, self.store)
        pid = result['id']
        self.assertEqual(len(self.store.proxy_sessions(pid)), 2)
        await control_service.execute('update_proxy_provider', {'provider_id': pid, 'usage_limit_gb': 0.2}, self.store)
        self.assertEqual(self.store.proxy_provider(pid)['usage_limit_bytes'], 200_000_000)
        parsed = await control_service.execute('parse_proxy_sessions', {'text': SAMPLE}, self.store)
        self.assertEqual(parsed['identity_kind'], 'port')
        self.assertEqual(parsed['session_ids'], ['10000'])
        await control_service.execute('add_proxy_sessions', {'provider_id': pid, 'raw_text': SAMPLE.replace('10000', '10002')}, self.store)
        self.assertEqual(len(self.store.proxy_sessions(pid)), 3)
        listing = await control_service.execute('proxy_providers', {}, self.store)
        public = next(p for p in listing['providers'] if p['id'] == pid)
        self.assertEqual(public['identity_kind'], 'port')
        self.assertEqual(public['usage_limit_gb'], 0.2)

    async def test_invalid_limit_does_not_leave_partial_provider(self):
        before = len(self.store.proxy_providers())
        with self.assertRaises(ValueError):
            await control_service.execute('add_proxy_provider', {
                'label': 'Bad', 'template': SAMPLE, 'usage_limit_gb': -1,
            }, self.store)
        self.assertEqual(len(self.store.proxy_providers()), before)
