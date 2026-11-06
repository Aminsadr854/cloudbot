import unittest
from unittest.mock import AsyncMock, patch

import providers


class UpCloudReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        providers.clear_cache()
        self.account = {"provider": "upcloud", "token": "secret", "proxy": None}

    async def test_server_list_normalizes_public_ip_and_uuid(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"servers": {"server": [{
            "uuid": "00000000-0000-0000-0000-000000000123",
            "title": "edge", "zone": "fi-hel1", "state": "started",
            "plan": "2xCPU-4GB", "ip_addresses": {"ip_address": [
                {"access": "private", "address": "10.0.0.3"},
                {"access": "public", "address": "198.51.100.10"},
            ]},
        }]}})
        result = await p.list_servers()
        self.assertEqual(result[0]["id"], "00000000-0000-0000-0000-000000000123")
        self.assertEqual(result[0]["ip"], "198.51.100.10")
        self.assertEqual(result[0]["ips"], ["198.51.100.10"])

    async def test_public_zones_and_catalogs(self):
        p = providers.Provider(self.account)

        async def request(method, path, **kwargs):
            if path == "/zone":
                return {"zones": {"zone": [
                    {"id": "fi-hel1", "title": "Helsinki", "public": True},
                    {"id": "private", "title": "Private", "public": False},
                ]}}
            if path == "/plan":
                return {"plans": {"plan": [{"name": "2xCPU-4GB", "title": "General", "core_number": 2,
                                                "memory_amount": 4096, "storage_size": 80,
                                                "price": {"amount": "20.00"}, "zones": ["fi-hel1"]}]}}
            if path == "/storage/template":
                return {"storages": {"storage": [
                    {"uuid": "tmpl-1", "title": "Ubuntu 24.04", "access": "public", "zone": "fi-hel1"},
                    {"uuid": "tmpl-other-zone", "title": "Debian 12", "access": "public", "zone": "uk-lon1"},
                    {"uuid": "private-1", "title": "secret", "access": "private"},
                ]}}
            return {}

        p._req = AsyncMock(side_effect=request)
        self.assertEqual(await p.regions(), [("fi-hel1", "Helsinki")])
        self.assertEqual((await p.plans("fi-hel1"))[0][0], "2xCPU-4GB")
        self.assertEqual(await p.images("fi-hel1"), [("tmpl-1", "Ubuntu 24.04")])

    async def test_official_paths_and_base(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"servers": {"server": []}})
        await p.list_servers()
        self.assertEqual(p._base(), providers.UPCLOUD)
        p._req.assert_awaited_once_with("GET", "/server")

    async def test_req_uses_upcloud_bearer_and_resolved_proxy(self):
        p = providers.Provider({**self.account, "proxy": "http://proxy:8080",
                                "proxy_family": "ipv4"})
        seen = {}

        class Response:
            status = 200
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            async def text(self):
                return '{"account": {"username": "owner"}}'
            async def json(self):
                return {"account": {"username": "owner"}}

        class Session:
            def __init__(self, **kwargs):
                seen["session"] = kwargs
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            def request(self, method, url, **kwargs):
                seen.update(method=method, url=url, request=kwargs)
                return Response()

        with patch.object(providers.aiohttp, "ClientSession", Session), \
             patch.object(providers.aiohttp, "ClientTimeout", return_value=object()), \
             patch.object(providers, "proxy_for_family", AsyncMock(return_value="http://resolved:8080")) as family:
            result = await p.whoami()
        self.assertEqual(result, "owner")
        self.assertEqual(seen["url"], providers.UPCLOUD + "/account")
        self.assertEqual(seen["request"]["headers"]["Authorization"], "Bearer secret")
        self.assertEqual(seen["request"]["proxy"], "http://resolved:8080")
        family.assert_awaited_once_with("http://proxy:8080", "ipv4")

    async def test_transport_errors_and_logs_redact_token_and_proxy_credentials(self):
        proxy = "http://user:proxy-secret@proxy.example:8080"
        p = providers.Provider({**self.account, "token": "api-secret", "proxy": proxy})

        class Session:
            def __init__(self, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            def request(self, method, url, **kwargs):
                raise RuntimeError(f"failed at {proxy} with api-secret")

        with patch.object(providers.aiohttp, "ClientSession", Session), \
             patch.object(providers.aiohttp, "ClientTimeout", return_value=object()), \
             patch.object(providers, "proxy_for_family", AsyncMock(return_value=proxy)), \
             self.assertLogs("cloudbot.providers", level="WARNING") as logs:
            with self.assertRaises(providers.ProviderError) as raised:
                await p._req("GET", "/account")
        for secret in ("api-secret", "proxy-secret", "http://user:"):
            self.assertNotIn(secret, str(raised.exception))
            self.assertNotIn(secret, "\n".join(logs.output))

    async def test_missing_networking_does_not_claim_public_ip(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"servers": {"server": [{"uuid": "u-1", "title": "edge"}]}})
        row = (await p.list_servers())[0]
        self.assertEqual(row["id"], "u-1")
        self.assertIsNone(row["ip"])
        self.assertEqual(row["ips"], [])

    def test_capabilities_are_stable_and_copied(self):
        caps = providers.provider_capabilities("upcloud")
        self.assertTrue(caps["server_lifecycle"])
        self.assertFalse(caps["ssh_key_crud"])
        caps["server_lifecycle"] = False
        self.assertTrue(providers.PROVIDER_CAPABILITIES["upcloud"]["server_lifecycle"])


class UpCloudLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.account = {"provider": "upcloud", "token": "secret", "proxy": None}

    async def test_create_uses_clone_storage_and_local_ssh_keys(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"server": {
            "uuid": "00000000-0000-0000-0000-000000000abc",
            "title": "edge", "zone": "fi-hel1", "plan": "2xCPU-4GB",
            "state": "maintenance", "password": "provider-one-time",
            "ip_addresses": {"ip_address": [{"access": "public", "address": "198.51.100.11"}]},
        }})
        result = await p.create_server(
            "edge", "fi-hel1", "2xCPU-4GB", "tmpl-1", "caller-secret",
            ssh_keys=["ssh-ed25519 AAAA local@example"],
        )
        body = p._req.await_args.kwargs["json"]["server"]
        self.assertEqual(body["title"], "edge")
        self.assertEqual(body["hostname"], "edge")
        self.assertEqual(body["zone"], "fi-hel1")
        self.assertEqual(body["plan"], "2xCPU-4GB")
        self.assertEqual(body["storage_devices"]["storage_device"][0]["action"], "clone")
        self.assertEqual(body["storage_devices"]["storage_device"][0]["storage"], "tmpl-1")
        self.assertEqual(body["login_user"]["username"], "root")
        self.assertEqual(body["login_user"]["ssh_keys"]["ssh_key"], ["ssh-ed25519 AAAA local@example"])
        self.assertEqual(result["id"], "00000000-0000-0000-0000-000000000abc")
        self.assertEqual(result["root_password"], "provider-one-time")

    async def test_create_does_not_store_caller_secret_when_provider_returns_none(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"server": {
            "uuid": "00000000-0000-0000-0000-000000000def",
            "title": "cloud-init", "zone": "fi-hel1", "plan": "2xCPU-4GB",
            "state": "maintenance",
        }})
        result = await p.create_server("cloud-init", "fi-hel1", "2xCPU-4GB", "tmpl-1", "caller-secret")
        self.assertNotIn("root_password", result)

    async def test_power_uses_upcloud_endpoints_and_string_uuid(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={})
        for action, endpoint in (("start", "start"), ("halt", "stop"),
                                 ("shutdown", "stop"), ("reboot", "restart")):
            await p.power_server("00000000-0000-0000-0000-000000000123", action)
            expected = {
                "start": {"server": {"start_type": "sync"}},
                "stop": {"stop_server": {"stop_type": "soft", "timeout": "60"}},
                "restart": {"restart_server": {
                    "stop_type": "soft", "timeout": "60", "timeout_action": "destroy",
                }},
            }[endpoint]
            self.assertEqual(
                p._req.await_args.args,
                ("POST", f"/server/00000000-0000-0000-0000-000000000123/{endpoint}"),
            )
            self.assertEqual(p._req.await_args.kwargs["json"], expected)

    def test_hostname_normalization(self):
        self.assertEqual(providers.sanitize_upcloud_hostname("My Edge_01.example"), "my-edge-01-example")
        self.assertEqual(providers.sanitize_upcloud_hostname("***"), "upcloud-server")
        value = providers.sanitize_upcloud_hostname("x" * 200 + "!")
        self.assertLessEqual(len(value), 128)
        self.assertTrue(value[0].isalnum() and value[-1].isalnum())

    async def test_create_keeps_title_and_sanitizes_hostname_separately(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"server": {
            "uuid": "u-host", "title": "My Edge_01.example", "zone": "fi-hel1",
            "plan": "2xCPU-4GB", "state": "maintenance",
        }})
        await p.create_server("My Edge_01.example", "fi-hel1", "2xCPU-4GB", "tmpl-1", "secret")
        body = p._req.await_args.kwargs["json"]["server"]
        self.assertEqual(body["title"], "My Edge_01.example")
        self.assertEqual(body["hostname"], "my-edge-01-example")

    async def test_delete_refuses_started_server_without_implicit_stop(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(return_value={"server": {"uuid": "u-1", "state": "started"}})
        with self.assertRaises(providers.ProviderError):
            await p.delete_server("u-1")
        self.assertEqual(p._req.await_args_list[0].args, ("GET", "/server/u-1"))
        self.assertEqual(p._req.await_count, 1)

    async def test_delete_stopped_server_skips_stop(self):
        p = providers.Provider(self.account)
        p._req = AsyncMock(side_effect=[{"server": {"state": "stopped"}}, {}])
        await p.delete_server("u-2")
        self.assertEqual([call.args for call in p._req.await_args_list], [
            ("GET", "/server/u-2"), ("DELETE", "/server/u-2?storages=1&backups=delete")
        ])

    async def test_resolve_ssh_keys_is_local_and_returns_public_strings(self):
        p = providers.Provider(self.account)
        keys = await p.resolve_ssh_keys_for_instance([
            {"name": "work", "public_key": " ssh-ed25519 AAAA work@example "},
            {"name": "empty", "public_key": ""},
        ])
        self.assertEqual(keys, ["ssh-ed25519 AAAA work@example"])


if __name__ == "__main__":
    unittest.main()
