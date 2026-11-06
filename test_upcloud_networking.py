import unittest
from unittest.mock import AsyncMock

import providers


class UpCloudNetworkingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.account = {"provider": "upcloud", "token": "secret", "proxy": None}

    async def test_ip_inventory_normalizes_nested_upcloud_rows_and_filters_server(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"ip_addresses": {"ip_address": [
            {"address": "198.51.100.10", "family": "IPv4", "server": "srv-1",
             "zone": "fi-hel1", "ptr_record": "edge.example", "floating": "no",
             "release_policy": "release"},
            {"address": "198.51.100.11", "family": "IPv4", "server": None,
             "zone": "fi-hel1", "ptr_record": "", "floating": "yes",
             "release_policy": "keep"},
        ]}})
        rows = await p.upcloud_ip_addresses("srv-1")
        self.assertEqual(rows, [{
            "address": "198.51.100.10", "family": "ipv4", "server_id": "srv-1",
            "zone": "fi-hel1", "ptr": "edge.example", "floating": False,
            "release_policy": "release",
        }])

    async def test_create_floating_ip_sends_explicit_release_policy_and_server(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(side_effect=[
            {"server": {"state": "stopped"}},
            {"networking": {"interfaces": {"interface": [
                {"index": 1, "type": "public", "mac": "00:16:3e:12:34:56"},
            ]}}},
            {"ip_address": {
                "address": "198.51.100.12", "family": "IPv4", "server": "srv-1",
                "zone": "fi-hel1", "floating": "yes", "release_policy": "keep",
            }},
        ])
        result = await p.create_upcloud_floating_ip("srv-1", "fi-hel1", "keep")
        self.assertEqual(result["address"], "198.51.100.12")
        method, path = p._req.await_args_list[2].args
        self.assertEqual((method, path), ("POST", "/ip_address"))
        self.assertEqual(p._req.await_args_list[2].kwargs["json"], {"ip_address": {
            "access": "public", "family": "IPv4", "floating": "yes",
            "zone": "fi-hel1", "server": "srv-1", "mac": "00:16:3e:12:34:56",
            "release_policy": "keep",
        }})

    async def test_attach_and_detach_use_patch_with_explicit_mac(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(side_effect=[
            {"server": {"state": "stopped"}},
            {"networking": {"interfaces": {"interface": [
                {"index": 1, "type": "public", "mac": "00:16:3e:12:34:56"},
            ]}}},
            {"ip_address": {"address": "198.51.100.12"}},
            {"ip_address": {"server": "srv-1"}},
            {"server": {"state": "stopped"}},
            {"ip_address": {"address": "198.51.100.12"}},
        ])
        await p.attach_upcloud_floating_ip("198.51.100.12", "srv-1")
        self.assertEqual(p._req.await_args_list[2].args, ("PATCH", "/ip_address/198.51.100.12"))
        self.assertEqual(p._req.await_args_list[2].kwargs["json"], {"ip_address": {
            "mac": "00:16:3e:12:34:56"}})
        await p.detach_upcloud_floating_ip("198.51.100.12")
        self.assertEqual(p._req.await_args_list[5].args, ("PATCH", "/ip_address/198.51.100.12"))
        self.assertEqual(p._req.await_args_list[5].kwargs["json"], {"ip_address": {"mac": None}})

    async def test_update_ptr_and_release_policy_uses_patch(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"ip_address": {"address": "198.51.100.12"}})
        await p.update_upcloud_ip("198.51.100.12", ptr="edge.example", release_policy="release")
        self.assertEqual(p._req.await_args.args, ("PATCH", "/ip_address/198.51.100.12"))
        self.assertEqual(p._req.await_args.kwargs["json"], {"ip_address": {
            "ptr_record": "edge.example", "release_policy": "release",
        }})

    async def test_networking_inventory_and_stopped_interface_ip_mutation(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(side_effect=[
            {"networking": {"interfaces": {"interface": [
                {"index": 2, "mac": "00:16:3e:12:34:56", "type": "private",
                 "ip_addresses": {"ip_address": [{"address": "10.0.0.4", "family": "IPv4"}]}}
            ]}}},
            {"server": {"state": "stopped"}},
            {"ip_address": {"address": "10.0.0.9", "family": "IPv4"}},
            {"server": {"state": "started"}},
        ])
        network = await p.upcloud_networking("srv-1")
        self.assertEqual(network["interfaces"][0]["index"], 2)
        await p.add_upcloud_interface_ip("srv-1", 2, "10.0.0.9", "IPv4")
        self.assertEqual(p._req.await_args_list[2].args,
                         ("POST", "/server/srv-1/networking/interface/2/ip_address"))
        with self.assertRaises(providers.ProviderError):
            await p.remove_upcloud_interface_ip("srv-1", 2, "10.0.0.9")

    async def test_delete_ip_requires_stopped_server_and_uses_address_path(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(side_effect=[
            {"ip_address": {"server": "srv-1"}},
            {"server": {"state": "stopped"}},
            None,
        ])
        await p.delete_upcloud_ip("198.51.100.12")
        self.assertEqual(p._req.await_args_list[-1].args,
                         ("DELETE", "/ip_address/198.51.100.12"))

    async def test_remove_interface_ip_uses_documented_delete_subresource(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(side_effect=[
            {"server": {"state": "stopped"}}, None,
        ])
        await p.remove_upcloud_interface_ip("srv-1", 2, "10.0.0.9")
        self.assertEqual(p._req.await_args_list[1].args,
                         ("DELETE", "/server/srv-1/networking/interface/2/ip_address/10.0.0.9"))

    async def test_invalid_release_policy_is_rejected_before_request(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock()
        with self.assertRaises(providers.ProviderError):
            await p.create_upcloud_floating_ip(None, "fi-hel1", "delete")
        p._req.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
