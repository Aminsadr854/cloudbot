import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import control_service
from store import Store


TOKEN = "upcloud-secret-token"
PROXY = "proxy.example:3128:proxy-user:proxy-password"


def account(account_id, provider="upcloud", label=None, proxy=None):
    return {
        "id": account_id,
        "label": label or f"{provider}-{account_id}",
        "provider": provider,
        "token": TOKEN,
        "proxy": proxy,
        "proxy_family": "default",
        "auto_backup": "disabled",
        "region": "FI",
        "created_at": 1,
    }


class MemoryStore:
    def __init__(self, accounts=()):
        self.rows = {row["id"]: dict(row) for row in accounts}
        self.cache = {}
        self.deleted_cache = []
        self.next_id = max(self.rows, default=0) + 1

    def accounts(self):
        return list(self.rows.values())

    def account(self, account_id):
        return self.rows.get(int(account_id))

    def add_account(self, label, provider, token, proxy=None, **kwargs):
        acc = account(self.next_id, provider, label, proxy)
        acc["token"] = token
        acc["region"] = kwargs.get("region", "")
        self.rows[self.next_id] = acc
        self.next_id += 1
        return acc["id"]

    def get_cache(self, key, default=None):
        return self.cache.get(key, default)

    def set_cache(self, key, value):
        self.cache[key] = value

    def set_account_region(self, account_id, region):
        self.rows[int(account_id)]["region"] = region

    def set_proxy(self, account_id, proxy, proxy_family="default", proxy_request=None):
        self.rows[int(account_id)]["proxy"] = proxy

    def allocate_proxy(self, provider_id, country, account_id, another=False):
        return {"proxy": PROXY, "family": "default", "country": country,
                "session": "session-1", "token": "reservation-token"}

    def delete_cache(self, key):
        self.deleted_cache.append(key)
        self.cache.pop(key, None)


class AccountFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_upcloud_images_are_fetched_and_cached_per_zone(self):
        store = MemoryStore([account(1)])
        provider = AsyncMock()
        provider.images.side_effect = lambda region=None, force=False: [(region, region)]
        control_service._OP_CACHE.clear()
        with patch.object(control_service, "Provider", return_value=provider):
            hel = await control_service.execute("images", {"account_id": 1, "region": "fi-hel1"}, store)
            lon = await control_service.execute("images", {"account_id": 1, "region": "uk-lon1"}, store)
            cached_hel = await control_service.execute("images", {"account_id": 1, "region": "fi-hel1"}, store)
        self.assertEqual(hel["images"][0]["id"], "fi-hel1")
        self.assertEqual(lon["images"][0]["id"], "uk-lon1")
        self.assertEqual(cached_hel, hel)
        self.assertEqual(provider.images.await_count, 2)
        self.assertEqual(provider.images.await_args_list[0].kwargs["region"], "fi-hel1")
        self.assertEqual(provider.images.await_args_list[1].kwargs["region"], "uk-lon1")

    async def test_add_upcloud_encrypts_token_and_proxy_and_masks_public_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "cloudbot.db"), os.path.join(tmp, "secret.key"))
            try:
                result = await control_service.execute("add_account", {
                    "label": "UpCloud FI", "provider": "upcloud",
                    "token": TOKEN, "proxy": PROXY, "region": "fi",
                }, store)
                row = store.con.execute("SELECT token, proxy FROM accounts").fetchone()
                self.assertNotIn(TOKEN.encode(), row[0])
                self.assertNotIn(PROXY.encode(), row[1])
                public = (await control_service.execute("accounts", {}, store))["accounts"][0]
                self.assertEqual(result["provider"], "upcloud")
                self.assertNotIn("token", public)
                self.assertNotIn("proxy", public)
                self.assertNotIn(TOKEN, json.dumps(public))
                self.assertNotIn("proxy-password", json.dumps(public))
                self.assertEqual(public["proxy_masked"], "configured")
            finally:
                store.close()

    async def test_add_account_allocation_response_does_not_include_proxy_secret(self):
        store = MemoryStore()
        result = await control_service.execute("add_account", {
            "label": "UpCloud allocated", "provider": "upcloud",
            "token": TOKEN, "region": "FI", "proxy_provider_id": 3,
        }, store)
        self.assertEqual(result["allocated_proxy"]["proxy_masked"], "configured")
        self.assertNotIn("proxy", result["allocated_proxy"])
        self.assertNotIn(PROXY, json.dumps(result))

    async def test_account_check_uses_upcloud_provider_and_redacts_route_secrets(self):
        store = MemoryStore([account(1, proxy=PROXY)])
        provider = AsyncMock()
        provider.whoami.return_value = "upcloud-user"
        provider.account_info.return_value = {"balance": 2.5, "credit": 3.0}
        with patch.object(control_service, "Provider", return_value=provider) as factory:
            result = await control_service.execute("test_account", {"account_id": 1}, store)
            all_result = await control_service.execute("check_all_accounts", {"refresh": True}, store)
        factory.assert_called()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["identity"], "upcloud-user")
        self.assertEqual(all_result["accounts"][0]["status"], "ok")
        sent_account = factory.call_args.args[0]
        self.assertEqual(sent_account["proxy"], PROXY)
        public_text = json.dumps(result) + json.dumps(all_result)
        self.assertNotIn(TOKEN, public_text)
        self.assertNotIn("proxy-password", public_text)

    async def test_mixed_server_and_floating_ip_aggregation_keeps_rows_and_errors(self):
        store = MemoryStore([account(1, "upcloud"), account(2, "vultr")])

        class FakeProvider:
            def __init__(self, row):
                self.provider = row["provider"]

            async def list_servers(self):
                if self.provider == "vultr":
                    raise RuntimeError("vultr route failed")
                return [{"id": "uc-1", "label": "upcloud-node", "ip": "198.51.100.10"}]

            async def upcloud_ip_addresses(self):
                return [{"address": "203.0.113.10", "family": "IPv4", "zone": "fi-hel1",
                         "server_id": "uc-1", "floating": True, "ptr": "node.example"}]

        def make_provider(row):
            return FakeProvider(row)

        with patch.object(control_service, "Provider", side_effect=make_provider):
            servers = await control_service.execute("all_servers", {"refresh": True}, store)
            fips = await control_service.execute("all_floating_ips", {"refresh": True}, store)
        self.assertEqual([s["id"] for s in servers["servers"]], ["uc-1"])
        self.assertIn("2", servers["account_errors"])
        self.assertEqual(fips["floating_ips"][0]["provider"], "upcloud")
        self.assertEqual(fips["floating_ips"][0]["ip"], "203.0.113.10")

    async def test_upcloud_catalog_refresh_falls_back_to_good_cached_result(self):
        store = MemoryStore([account(1)])
        cached = {"regions": [{"id": "fi-hel1", "label": "Finland"}]}
        store.set_cache("regions:upcloud:1", cached)
        provider = AsyncMock()
        provider.provider = "upcloud"
        provider.regions.side_effect = RuntimeError("refresh failed")
        with patch.object(control_service, "Provider", return_value=provider):
            result = await control_service.execute("regions", {
                "account_id": 1, "refresh": True,
            }, store)
        self.assertEqual(result, cached)

    async def test_floating_ip_refresh_keeps_good_rows_and_reports_redacted_account_error(self):
        store = MemoryStore([account(1, "upcloud"), account(2, "upcloud", proxy=PROXY)])

        class FakeProvider:
            def __init__(self, row):
                self.row = row

            async def upcloud_ip_addresses(self):
                if self.row["id"] == 2:
                    raise RuntimeError(f"route failed for {TOKEN} via {PROXY}")
                return [{"address": "203.0.113.11", "family": "IPv4", "zone": "fi-hel1",
                         "server_id": None, "floating": True}]

        with patch.object(control_service, "Provider", side_effect=FakeProvider):
            result = await control_service.execute("all_floating_ips", {"refresh": True}, store)
        self.assertEqual([row["ip"] for row in result["floating_ips"]], ["203.0.113.11"])
        self.assertIn("2", result["account_errors"])
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(PROXY, json.dumps(result))

    async def test_account_failure_redacts_token_and_proxy(self):
        store = MemoryStore([account(1, proxy=PROXY)])
        provider = AsyncMock()
        provider.whoami.side_effect = RuntimeError(f"unauthorized {TOKEN} via {PROXY}")
        with patch.object(control_service, "Provider", return_value=provider):
            result = await control_service.execute("test_account", {"account_id": 1}, store)
        self.assertEqual(result["status"], "error")
        self.assertNotIn(TOKEN, result["error"])
        self.assertNotIn(PROXY, result["error"])

    async def test_account_mutation_invalidates_shared_caches(self):
        store = MemoryStore()
        for key in ("all_servers", "all_floating_ips", "all_billing"):
            store.set_cache(key, {"stale": True})
        await control_service.execute("add_account", {
            "label": "UpCloud", "provider": "upcloud", "token": TOKEN,
        }, store)
        self.assertEqual(set(store.deleted_cache), {
            "all_servers", "all_floating_ips", "all_billing",
        })

    async def test_region_and_proxy_mutations_invalidate_inventory_caches(self):
        for operation, args in (
            ("set_account_region", {"account_id": 1, "region": "DE"}),
            ("set_account_proxy", {"account_id": 1, "proxy": PROXY}),
            ("allocate_account_proxy", {"account_id": 1, "provider_id": 3}),
        ):
            store = MemoryStore([account(1)])
            for key in ("all_servers", "all_floating_ips", "all_billing"):
                store.set_cache(key, {"stale": True})
            await control_service.execute(operation, args, store)
            self.assertTrue({"all_servers", "all_floating_ips", "all_billing"}
                            <= set(store.deleted_cache), operation)

    async def test_upcloud_ip_inventory_error_is_reported_with_servers_kept(self):
        store = MemoryStore([account(1)])

        class FailingInventory:
            async def list_servers(self):
                return [{"id": "uc-1", "label": "node"}]

            async def upcloud_ip_addresses(self):
                raise RuntimeError(f"inventory failed for {TOKEN}")

        with patch.object(control_service, "Provider", return_value=FailingInventory()), \
                self.assertLogs("cloudbot.control_service", level="WARNING") as logs:
            result = await control_service.execute("all_servers", {"refresh": True}, store)
        self.assertEqual([row["id"] for row in result["servers"]], ["uc-1"])
        self.assertIn("1", result["account_errors"])
        self.assertNotIn(TOKEN, result["account_errors"]["1"])
        self.assertNotIn(TOKEN, "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
