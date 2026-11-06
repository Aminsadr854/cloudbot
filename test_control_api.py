import unittest
import os
import json
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer

import control_service
from control_api import build_app


ACCOUNT = {
    "id": 7, "label": "Example", "provider": "vultr", "token": "private-token",
    "proxy": "private-proxy", "proxy_family": "ipv4", "auto_backup": "disabled",
    "note": "sample note",
    "created_at": 1,
}


class FakeStore:
    def __init__(self):
        self.password = None
        self.closed = False
        self._keys = []

    def accounts(self):
        return [ACCOUNT]

    def account(self, account_id):
        return ACCOUNT if account_id == 7 else None

    def set_account_note(self, account_id, note):
        if account_id == 7:
            ACCOUNT["note"] = note

    def set_server_pass(self, account_id, server_id, password):
        self.password = (account_id, server_id, password)

    def ssh_keys(self):
        return list(self._keys)

    def ssh_key(self, key_id):
        return next((k for k in self._keys if k["id"] == key_id), None)

    def add_ssh_key(self, name, public_key):
        k = {"id": len(self._keys) + 1, "name": name, "public_key": public_key}
        self._keys.append(k)
        return k["id"]

    def delete_ssh_key(self, key_id):
        self._keys = [k for k in self._keys if k["id"] != key_id]
        return True

    def close(self):
        self.closed = True


class ControlApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = FakeStore()
        self.client = TestClient(TestServer(build_app(token="x" * 48,
                                                      store_factory=lambda: self.store)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()

    async def request(self, operation, args=None, authorized=True):
        headers = {"Authorization": "Bearer " + "x" * 48} if authorized else {}
        return await self.client.post(f"/v1/operations/{operation}",
                                      json=args or {}, headers=headers)

    async def test_authentication_and_account_redaction(self):
        denied = await self.request("accounts", authorized=False)
        self.assertEqual(denied.status, 401)
        allowed = await self.request("accounts")
        self.assertEqual(allowed.status, 200)
        data = await allowed.json()
        self.assertEqual(data["accounts"][0]["id"], 7)
        self.assertEqual(data["accounts"][0]["note"], "sample note")
        self.assertNotIn("token", data["accounts"][0])
        self.assertNotIn("proxy", data["accounts"][0])
        self.assertTrue(self.store.closed)

    async def test_set_account_note_operation(self):
        allowed = await self.request("set_account_note", {"account_id": 7, "note": "updated memo"})
        self.assertEqual(allowed.status, 200)
        data = await allowed.json()
        self.assertTrue(data.get("updated"))
        self.assertEqual(data["account"]["note"], "updated memo")

    async def test_create_requires_confirmation_and_hides_password(self):
        provider = AsyncMock()
        provider.create_server.return_value = {
            "id": "server-1", "label": "node-01", "ip": "203.0.113.1",
            "root_password": "provider-password", "default_password": "provider-password",
        }
        with patch.object(control_service, "Provider", return_value=provider):
            body = {"account_id": 7, "name": "node-01", "region": "ewr",
                    "plan": "vc2-1c-1gb", "image": "1743"}
            denied = await self.request("create_server", body)
            self.assertEqual(denied.status, 400)
            provider.create_server.assert_not_awaited()
            allowed = await self.request("create_server", {**body, "confirm": "CREATE_SERVER"})
        self.assertEqual(allowed.status, 200)
        result = await allowed.json()
        self.assertNotIn("root_password", result["server"])
        self.assertNotIn("default_password", result["server"])
        self.assertEqual(self.store.password, (7, "server-1", "provider-password"))

    async def test_create_server_auto_injects_vault_ssh_keys(self):
        self.store.add_ssh_key("main", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG123 test@vault")
        provider = AsyncMock()
        provider.create_server.return_value = {
            "id": "srv-1", "label": "node-01", "ip": "203.0.113.1",
            "root_password": "provider-password",
        }
        provider.resolve_ssh_keys_for_instance.return_value = ["v-key-uuid-1"]
        with patch.object(control_service, "Provider", return_value=provider):
            body = {"account_id": 7, "name": "node-01", "region": "ewr",
                    "plan": "vc2-1c-1gb", "image": "1743", "confirm": "CREATE_SERVER"}
            res = await self.request("create_server", body)
        self.assertEqual(res.status, 200)
        provider.resolve_ssh_keys_for_instance.assert_awaited_once()
        called_keys = provider.create_server.call_args[1]["ssh_keys"]
        self.assertEqual(called_keys, ["v-key-uuid-1"])

    async def test_create_server_with_explicit_ssh_key_name(self):
        self.store.add_ssh_key("main", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG123 test@vault")
        provider = AsyncMock()
        provider.create_server.return_value = {
            "id": "srv-2", "label": "node-02", "ip": "203.0.113.2",
            "root_password": "provider-password",
        }
        provider.resolve_ssh_keys_for_instance.return_value = ["v-key-uuid-2"]
        with patch.object(control_service, "Provider", return_value=provider):
            body = {"account_id": 7, "name": "node-02", "region": "ewr",
                    "plan": "vc2-1c-1gb", "image": "1743", "confirm": "CREATE_SERVER",
                    "ssh_keys": ["main"]}
            res = await self.request("create_server", body)
        self.assertEqual(res.status, 200)
        called_keys = provider.create_server.call_args[1]["ssh_keys"]
        self.assertEqual(called_keys, ["v-key-uuid-2"])

    async def test_power_confirmation_must_match_action(self):
        provider = AsyncMock()
        with patch.object(control_service, "Provider", return_value=provider):
            response = await self.request("power_server", {
                "account_id": 7, "server_id": "server-1", "action": "halt",
                "confirm": "REBOOT"})
        self.assertEqual(response.status, 400)
        provider.vultr_power.assert_not_awaited()

    async def test_mcp_tool_calls_the_authenticated_api(self):
        from mcp import Client
        from mcp_server import mcp

        with patch.dict(os.environ, {"CLOUDBOT_CONTROL_URL": str(self.client.make_url(""))}), \
                patch("mcp_server.read_token", return_value="x" * 48):
            async with Client(mcp) as client:
                result = await client.call_tool("list_accounts", {})
        self.assertFalse(result.is_error, repr(result))
        self.assertEqual(json.loads(result.content[0].text)["accounts"][0]["id"], 7)

    async def test_mcp_tool_surfaces_api_error_text(self):
        from mcp import Client
        from mcp_server import mcp

        with patch.dict(os.environ, {"CLOUDBOT_CONTROL_URL": str(self.client.make_url(""))}), \
                patch("mcp_server.read_token", return_value="x" * 48):
            async with Client(mcp) as client:
                result = await client.call_tool("power_server", {
                    "account_id": 7, "server_id": "server-1", "action": "halt",
                    "confirm": "REBOOT"})
        self.assertTrue(result.is_error)
        self.assertNotIn("Error executing tool power_server\n", result.content[0].text + "\n")
        self.assertGreater(len(result.content[0].text), len("Error executing tool power_server"))


class McpRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_expected_tools_are_registered(self):
        from mcp import Client
        from mcp_server import mcp

        async with Client(mcp) as client:
            tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}
        expected = {
            "list_accounts", "create_server", "delete_server", "server_password",
            "set_server_password", "add_ssh_key", "delete_ssh_key",
            "assign_floating_ip", "unassign_floating_ip", "update_floating_ip",
            "create_hetzner_primary_ip", "assign_hetzner_primary_ip",
            "unassign_hetzner_primary_ip", "delete_hetzner_primary_ip",
            "delete_dns_record", "resource_limits", "upsert_dns",
            "watchdog_status", "delete_floating_ip", "all_servers",
            "check_all_accounts", "list_ssh_keys", "proxy_pool",
            "set_account_note", "add_account"
        }
        self.assertTrue(expected <= names, f"Missing tools: {expected - names}")

        # Verify add_account schema includes note parameter
        add_tool = next(t for t in tools.tools if t.name == "add_account")
        add_props = (getattr(add_tool, "input_schema", None) or getattr(add_tool, "inputSchema", {})).get("properties", {})
        self.assertIn("note", add_props)

        # Verify create_server schema includes SSH parameters
        create_tool = next(t for t in tools.tools if t.name == "create_server")
        schema_props = (getattr(create_tool, "input_schema", None) or getattr(create_tool, "inputSchema", {})).get("properties", {})
        self.assertIn("ssh_key_ids", schema_props)
        self.assertIn("ssh_keys", schema_props)
        self.assertIn("use_vault_keys", schema_props)


class UpCloudStore(FakeStore):
    def __init__(self):
        super().__init__()
        self.deleted = []
        self.account_row = {**ACCOUNT, "provider": "upcloud", "token": "private-token"}

    def accounts(self):
        return [self.account_row]

    def account(self, account_id):
        return self.account_row if account_id == 7 else None

    def delete_server_pass(self, account_id, server_id):
        self.deleted.append((account_id, str(server_id)))


class ControlServiceUpCloudTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = UpCloudStore()
        self.client = TestClient(TestServer(build_app(token="x" * 48,
                                                      store_factory=lambda: self.store)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()

    async def request(self, operation, args=None):
        return await self.client.post(
            f"/v1/operations/{operation}", json=args or {},
            headers={"Authorization": "Bearer " + "x" * 48})

    async def test_create_dispatches_upcloud_and_stores_provider_password(self):
        provider = AsyncMock()
        provider.create_server.return_value = {
            "id": "00000000-0000-0000-0000-000000000abc",
            "label": "edge", "ip": "198.51.100.11",
            "root_password": "provider-one-time",
        }
        body = {"account_id": 7, "name": "edge", "region": "fi-hel1",
                "plan": "2xCPU-4GB", "image": "tmpl-1", "confirm": "CREATE_SERVER"}
        with patch.object(control_service, "Provider", return_value=provider):
            response = await self.request("create_server", body)
        self.assertEqual(response.status, 200)
        result = await response.json()
        self.assertEqual(result["server"]["id"], "00000000-0000-0000-0000-000000000abc")
        self.assertTrue(result["password_stored"])
        self.assertEqual(self.store.password, (7, "00000000-0000-0000-0000-000000000abc", "provider-one-time"))
        provider.create_server.assert_awaited_once()

    async def test_create_without_provider_password_does_not_store_generated_fallback(self):
        provider = AsyncMock()
        provider.create_server.return_value = {
            "id": "00000000-0000-0000-0000-000000000def", "label": "edge",
        }
        body = {"account_id": 7, "name": "edge", "region": "fi-hel1",
                "plan": "2xCPU-4GB", "image": "tmpl-1", "confirm": "CREATE_SERVER"}
        with patch.object(control_service, "Provider", return_value=provider):
            response = await self.request("create_server", body)
        self.assertEqual(response.status, 200)
        result = await response.json()
        self.assertFalse(result["password_stored"])
        self.assertIsNone(self.store.password)

    async def test_delete_and_power_keep_exact_confirmation_values(self):
        provider = AsyncMock()
        with patch.object(control_service, "Provider", return_value=provider):
            denied = await self.request("delete_server", {
                "account_id": 7, "server_id": "00000000-0000-0000-0000-000000000123",
                "confirm": "DELETE"})
            self.assertEqual(denied.status, 400)
            deleted = await self.request("delete_server", {
                "account_id": 7, "server_id": "00000000-0000-0000-0000-000000000123",
                "confirm": "DELETE_SERVER"})
            powered = await self.request("power_server", {
                "account_id": 7, "server_id": "00000000-0000-0000-0000-000000000123",
                "action": "shutdown", "confirm": "SHUTDOWN"})
        self.assertEqual(deleted.status, 200)
        self.assertEqual(powered.status, 200)
        provider.delete_server.assert_awaited_once_with("00000000-0000-0000-0000-000000000123")
        provider.power_server.assert_awaited_once_with("00000000-0000-0000-0000-000000000123", "shutdown")
        self.assertEqual(self.store.deleted, [(7, "00000000-0000-0000-0000-000000000123")])

    async def test_upcloud_networking_operation_uses_string_uuid(self):
        provider = AsyncMock()
        provider.upcloud_networking.return_value = {
            "server_id": "00000000-0000-0000-0000-000000000123",
            "interfaces": [],
        }
        with patch.object(control_service, "Provider", return_value=provider):
            result = await control_service.execute("upcloud_networking", {
                "account_id": "7",
                "server_id": "00000000-0000-0000-0000-000000000123",
            }, self.store)
        provider.upcloud_networking.assert_awaited_once_with(
            "00000000-0000-0000-0000-000000000123")
        self.assertEqual(result["networking"]["interfaces"], [])

    async def test_upcloud_interface_mutation_requires_exact_confirmation(self):
        provider = AsyncMock()
        with patch.object(control_service, "Provider", return_value=provider):
            with self.assertRaises(control_service.InputError):
                await control_service.execute("upcloud_add_interface_ip", {
                    "account_id": "7", "server_id": "uuid-1",
                    "interface_index": "2", "address": "10.0.0.9",
                    "confirm": "ADD_IP",
                }, self.store)
            await control_service.execute("upcloud_add_interface_ip", {
                "account_id": "7", "server_id": "uuid-1",
                "interface_index": "2", "address": "10.0.0.9",
                "confirm": "ADD_INTERFACE_IP",
            }, self.store)
        provider.add_upcloud_interface_ip.assert_awaited_once_with(
            "uuid-1", 2, address="10.0.0.9", family="IPv4", force=False)


class UpCloudIpUpdateConfirmationTests(unittest.IsolatedAsyncioTestCase):
    async def test_ptr_and_release_policy_update_requires_exact_confirmation(self):
        store = UpCloudStore()
        provider = AsyncMock()
        args = {"account_id": "7", "floating_id": "198.51.100.2",
                "ptr": "edge.example", "release_policy": "keep"}
        with patch.object(control_service, "Provider", return_value=provider):
            with self.assertRaises(control_service.InputError):
                await control_service.execute("update_floating_ip", args, store)
            result = await control_service.execute("update_floating_ip", {
                **args, "confirm": "UPDATE_FLOATING_IP"}, store)
        provider.update_upcloud_ip.assert_awaited_once_with(
            "198.51.100.2", ptr="edge.example", release_policy="keep")
        self.assertTrue(result["updated"])
