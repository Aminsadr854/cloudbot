import unittest
from unittest.mock import AsyncMock

from providers import Provider, server_warnings


class HetznerIPBlockTests(unittest.IsolatedAsyncioTestCase):
    async def test_running_unlocked_server_preserves_ip_blocks_in_list_and_detail(self):
        for ipv4_blocked, ipv6_blocked in [(True, True), (True, False), (False, True), (False, False)]:
            with self.subTest(ipv4=ipv4_blocked, ipv6=ipv6_blocked):
                raw = {"id": 1, "name": "node", "status": "running", "locked": False,
                       "public_net": {"ipv4": {"ip": "192.0.2.1", "blocked": ipv4_blocked},
                                      "ipv6": {"ip": "2001:db8::/64", "blocked": ipv6_blocked}}}
                provider = Provider({"provider": "hetzner", "token": "test"})
                provider._req = AsyncMock(return_value={"servers": [raw]})
                listed = (await provider.list_servers())[0]
                provider._req = AsyncMock(return_value={"server": raw})
                detailed = await provider.server(1)
                for result in (listed, detailed):
                    self.assertEqual(result["status"], "running")
                    self.assertFalse(result["locked"])
                    self.assertEqual(result["ipv4_blocked"], ipv4_blocked)
                    self.assertEqual(result["ipv6_blocked"], ipv6_blocked)
                    self.assertEqual(result["ip_blocked"], ipv4_blocked or ipv6_blocked)
                    expected = (["192.0.2.1"] if ipv4_blocked else []) + (["2001:db8::/64"] if ipv6_blocked else [])
                    self.assertEqual(result["blocked_ips"], expected)
                    warnings = server_warnings([result])
                    self.assertEqual(len(warnings), int(bool(expected)))
                    if expected:
                        self.assertEqual(warnings[0]["kind"], "ip_blocked")
                        self.assertEqual(warnings[0]["blocked_ips"], expected)

    async def test_unassigned_families_and_independent_server_lock(self):
        provider = Provider({"provider": "hetzner", "token": "test"})
        provider._req = AsyncMock(return_value={"server": {"id": 2, "locked": True,
                                                          "public_net": {"ipv4": None, "ipv6": None}}})
        result = await provider.server(2)
        self.assertFalse(result["ip_blocked"])
        self.assertEqual(result["blocked_ips"], [])
        self.assertEqual([w["kind"] for w in server_warnings([result])], ["locked"])


if __name__ == "__main__":
    unittest.main()
