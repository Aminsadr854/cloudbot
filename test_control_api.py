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
    "created_at": 1,
}


class FakeStore:
    def __init__(self):
        self.password = None
        self.closed = False

    def accounts(self):
        return [ACCOUNT]

    def account(self, account_id):
        return ACCOUNT if account_id == 7 else None

    def set_server_pass(self, account_id, server_id, password):
        self.password = (account_id, server_id, password)

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
        self.assertNotIn("token", data["accounts"][0])
        self.assertNotIn("proxy", data["accounts"][0])
        self.assertTrue(self.store.closed)

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


class McpRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_expected_tools_are_registered(self):
        from mcp import Client
        from mcp_server import mcp

        async with Client(mcp) as client:
            tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}
        self.assertTrue({"list_accounts", "create_server", "upsert_dns",
                         "watchdog_status", "delete_floating_ip"} <= names)
