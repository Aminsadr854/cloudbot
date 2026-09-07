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
