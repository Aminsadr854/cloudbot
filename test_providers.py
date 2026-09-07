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
