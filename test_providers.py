import socket
import unittest
from unittest.mock import AsyncMock, patch

import providers


class ProxyParsingTests(unittest.TestCase):
    def test_bracketed_ipv6_proxy_is_accepted(self):
        self.assertEqual(
            providers.proxy_url("[2001:db8::1]:1080:user:pass"),
            "http://user:pass@[2001:db8::1]:1080",
        )


class LocationFormattingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        providers.clear_cache()

    def tearDown(self):
        providers.clear_cache()

    def test_country_flag_uses_iso_regional_indicators(self):
        self.assertEqual(providers.country_flag("de"), "🇩🇪")
        self.assertEqual(providers.country_flag("United States"), "🇺🇸")

    def test_location_text_uses_provider_region_fallback(self):
        self.assertEqual(providers.location_text("vultr", "fra"), "🇩🇪 fra")
        self.assertEqual(providers.location_text("linode", "us-east"), "🇺🇸 us-east")

    async def test_country_flag_is_added_to_region_choices(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={
            "regions": [{"id": "fra", "city": "Frankfurt", "country": "DE"}]
        })
        regions = await p.regions()
        self.assertEqual(regions, [("fra", "🇩🇪 Frankfurt DE")])


class PlanFormattingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        providers.clear_cache()

    def tearDown(self):
        providers.clear_cache()

    async def test_linode_plan_shows_monthly_transfer(self):
        p = providers.Provider({"provider": "linode", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={"data": [{
            "id": "g6-standard-1", "label": "Linode 2GB", "transfer": 2000,
            "price": {"monthly": 12},
        }]})

        self.assertEqual(await p.plans(), [
            ("g6-standard-1", "Linode 2GB · 📡 2000 GB traffic - $12/mo")
        ])


class CacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        providers.clear_cache()

    def tearDown(self):
        providers.clear_cache()

    async def test_regions_are_cached_across_calls(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={
            "regions": [{"id": "ams", "city": "Amsterdam", "country": "NL"}]
        })
        first = await p.regions()
        second = await p.regions()
        self.assertEqual(first, second)
        self.assertEqual(p._req.await_count, 1)

    async def test_regions_force_refresh_bypasses_cache(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={
            "regions": [{"id": "ams", "city": "Amsterdam", "country": "NL"}]
        })
        await p.regions()
        await p.regions(force=True)
        self.assertEqual(p._req.await_count, 2)

    async def test_plans_are_cached_per_region(self):
        p = providers.Provider({"provider": "linode", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={"data": [{
            "id": "g6-standard-1", "label": "Linode 2GB", "transfer": 2000,
            "price": {"monthly": 12},
        }]})
        first = await p.plans("us-east")
        second = await p.plans("us-east")
        self.assertEqual(first, second)
        self.assertEqual(p._req.await_count, 1)

        p._req.return_value = {"data": [{
            "id": "g6-standard-2", "label": "Linode 4GB", "transfer": 4000,
            "price": {"monthly": 24},
        }]}
        third = await p.plans("eu-central")
        self.assertEqual(p._req.await_count, 2)
        self.assertNotEqual(first, third)

    async def test_clear_cache_by_provider_or_all(self):
        p_vultr = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p_vultr._req = AsyncMock(return_value={"regions": [{"id": "ams", "city": "Amsterdam", "country": "NL"}]})
        p_linode = providers.Provider({"provider": "linode", "token": "test", "proxy": None})
        p_linode._req = AsyncMock(return_value={"data": [{"id": "us-east", "label": "Newark, NJ", "country": "US"}]})

        await p_vultr.regions()
        await p_linode.regions()
        self.assertIsNotNone(providers.get_cached_regions("vultr"))
        self.assertIsNotNone(providers.get_cached_regions("linode"))

        # Clear only vultr
        providers.clear_cache("vultr")
        self.assertIsNone(providers.get_cached_regions("vultr"))
        self.assertIsNotNone(providers.get_cached_regions("linode"))

        # Clear all
        providers.clear_cache()
        self.assertIsNone(providers.get_cached_regions("linode"))


class VultrBackupsAndAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        providers.clear_cache()

    def tearDown(self):
        providers.clear_cache()

    async def test_vultr_plans_filtered_by_region(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        async def mock_req(method, path, **kwargs):
            if path == "/regions/ams/availability":
                return {"available_plans": ["vc2-1c-1gb"]}
            if path.startswith("/plans"):
                return {"plans": [
                    {"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "monthly_cost": 5, "locations": ["ams", "ewr"]},
                    {"id": "vc2-1c-0.5gb-v6", "vcpu_count": 1, "ram": 512, "disk": 10, "monthly_cost": 2.5, "locations": ["ewr", "atl"]},
                ]}
            return {}
        p._req = AsyncMock(side_effect=mock_req)
        plans = await p.plans("ams")
        # Should only contain vc2-1c-1gb, vc2-1c-0.5gb-v6 must be excluded
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0][0], "vc2-1c-1gb")

    async def test_vultr_create_server_disables_backup_by_default(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={"instance": {
            "id": "inst-1", "label": "srv1", "main_ip": "1.2.3.4",
            "region": "ams", "plan": "vc2-1c-1gb", "default_password": "pass"
        }})
        await p.create_server("srv1", "ams", "vc2-1c-1gb", "1743", "rootpw")
        call_args = p._req.call_args
        self.assertEqual(call_args[0][0], "POST")
        self.assertEqual(call_args[0][1], "/instances")
        body = call_args[1]["json"]
        self.assertEqual(body["backups"], "disabled")

    async def test_vultr_create_server_enables_backup_when_specified(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={"instance": {
            "id": "inst-1", "label": "srv1", "main_ip": "1.2.3.4",
            "region": "ams", "plan": "vc2-1c-1gb", "default_password": "pass"
        }})
        await p.create_server("srv1", "ams", "vc2-1c-1gb", "1743", "rootpw", auto_backup="enabled")
        body = p._req.call_args[1]["json"]
        self.assertEqual(body["backups"], "enabled")

    async def test_set_vultr_backups(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={"instance": {"id": "inst-1"}})
        await p.set_vultr_backups("inst-1", "disabled")
        p._req.assert_called_once_with("PATCH", "/instances/inst-1", json={"backups": "disabled"})


class ProxyFamilyTests(unittest.IsolatedAsyncioTestCase):
    async def test_ipv4_replaces_dual_stack_proxy_hostname(self):
        loop = __import__("asyncio").get_running_loop()
        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.9", 8080))]
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=rows)):
            self.assertEqual(
                await providers.proxy_for_family("http://user:pass@proxy.example:8080", "ipv4"),
                "http://user:pass@192.0.2.9:8080",
            )

    async def test_ipv6_replaces_dual_stack_proxy_hostname(self):
        loop = __import__("asyncio").get_running_loop()
        rows = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::9", 8080, 0, 0))]
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=rows)):
            self.assertEqual(
                await providers.proxy_for_family("socks5://proxy.example:8080", "ipv6"),
                "socks5://[2001:db8::9]:8080",
            )

    async def test_requested_missing_family_has_clear_error(self):
        loop = __import__("asyncio").get_running_loop()
        with patch.object(loop, "getaddrinfo", new=AsyncMock(side_effect=socket.gaierror())):
            with self.assertRaisesRegex(providers.ProviderError, "no IPV6 address"):
                await providers.proxy_for_family("http://proxy.example:8080", "ipv6")


class VultrIpTests(unittest.IsolatedAsyncioTestCase):
    def _provider(self):
        return providers.Provider({"provider": "vultr", "token": "test", "proxy": None})

    async def test_add_ipv4_requests_reboot(self):
        p = self._provider()
        p._req = AsyncMock(return_value={"ip": "198.51.100.10"})
        self.assertEqual(await p.add_vultr_ipv4("instance-1"), {"ip": "198.51.100.10"})
        p._req.assert_awaited_once_with("POST", "/instances/instance-1/ipv4", json={"reboot": True})

    async def test_create_and_attach_floating_ip(self):
        p = self._provider()
        p._req = AsyncMock(side_effect=[
            {"reserved_ip": {"id": "rip-1", "ip_address": "198.51.100.20"}}, {}
        ])
        got = await p.create_and_attach_vultr_floating_ip("instance-1", "ewr", "cloudbot-test")
        self.assertEqual(got["ip_address"], "198.51.100.20")
        self.assertEqual(p._req.await_args_list[0].args, ("POST", "/reserved-ips"))
        self.assertEqual(p._req.await_args_list[0].kwargs["json"],
                         {"region": "ewr", "ip_type": "v4", "label": "cloudbot-test"})
        self.assertEqual(p._req.await_args_list[1].args,
                         ("POST", "/reserved-ips/rip-1/attach"))
        self.assertEqual(p._req.await_args_list[1].kwargs["json"], {"instance_id": "instance-1"})

    async def test_lists_only_floating_ips_for_requested_instance(self):
        p = self._provider()
        p._req = AsyncMock(return_value={"reserved_ips": [
            {"id": "one", "instance_id": "instance-1"},
            {"id": "two", "instance_id": "instance-2"},
        ]})
        self.assertEqual(await p.vultr_floating_ips("instance-1"),
                         [{"id": "one", "instance_id": "instance-1"}])
        p._req.assert_awaited_once_with("GET", "/reserved-ips?per_page=500")

    async def test_power_and_delete_use_correct_vultr_endpoints(self):
        p = self._provider()
        p._req = AsyncMock(return_value={})
        await p.vultr_power("instance-1", "reboot")
        await p.delete_vultr_floating_ip("rip-1")
        self.assertEqual(p._req.await_args_list[0].args, ("POST", "/instances/instance-1/reboot"))
        self.assertEqual(p._req.await_args_list[1].args, ("DELETE", "/reserved-ips/rip-1"))

    async def test_get_floating_ip_uses_its_id(self):
        p = self._provider()
        p._req = AsyncMock(return_value={"reserved_ip": {"id": "rip-1", "subnet": "198.51.100.20"}})
        self.assertEqual(await p.vultr_floating_ip("rip-1"),
                         {"id": "rip-1", "subnet": "198.51.100.20"})
        p._req.assert_awaited_once_with("GET", "/reserved-ips/rip-1")


class AccountInfoTests(unittest.IsolatedAsyncioTestCase):
    async def test_vultr_account_info_parses_credit_and_charges(self):
        p = providers.Provider({"provider": "vultr", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={
            "account": {
                "name": "Test User",
                "email": "user@example.com",
                "balance": -300.0,
                "pending_charges": 60.0,
                "last_payment_date": "2026-09-03T04:21:03+00:00",
                "last_payment_amount": -300.0,
            }
        })
        info = await p.account_info()
        self.assertEqual(info["credit"], 300.0)
        self.assertEqual(info["pending_charges"], 60.0)
        self.assertEqual(info["net"], 240.0)
        self.assertEqual(info["last_payment_date"], "2026-09-03")

    async def test_linode_account_info_parses_promotions_and_balance(self):
        p = providers.Provider({"provider": "linode", "token": "test", "proxy": None})
        p._req = AsyncMock(return_value={
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "balance": 0.0,
            "balance_uninvoiced": 15.5,
            "active_promotions": [{"credit_remaining": "250.00"}],
        })
        info = await p.account_info()
        self.assertEqual(info["credit"], 250.0)
        self.assertEqual(info["pending_charges"], 15.5)
        self.assertEqual(info["net"], 234.5)
