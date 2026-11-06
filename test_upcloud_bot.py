import importlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch


class UpCloudTelegramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = patch.dict(os.environ, {
            "CLOUDBOT_TOKEN": "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
            "CLOUDBOT_OWNER": "123",
            "CLOUDBOT_DB": os.path.join(cls.tmp.name, "cloudbot.db"),
            "CLOUDBOT_KEY": os.path.join(cls.tmp.name, "cloudbot.key"),
        })
        cls.env.start()
        cls.bot = importlib.import_module("bot")

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.tmp.cleanup()

    def button_data(self, markup):
        return [button.callback_data for row in markup.inline_keyboard for button in row]

    def test_upcloud_label_and_provider_picker(self):
        self.assertIn("upcloud", self.bot.PROVIDER_LABEL)
        with patch.object(self.bot.st, "accounts", return_value=[]):
            markup = self.bot.kb_accounts()
        # Verify the account creation wizard itself offers the provider.
        import asyncio
        from unittest.mock import AsyncMock
        cb = SimpleNamespace(message=SimpleNamespace(edit_text=AsyncMock()), answer=AsyncMock())
        state = SimpleNamespace(get_data=AsyncMock(return_value={}), clear=AsyncMock(),
                                update_data=AsyncMock(), set_state=AsyncMock())
        asyncio.run(self.bot.add_start(cb, state))
        picker = cb.message.edit_text.await_args.kwargs["reply_markup"]
        self.assertIn("prov:upcloud", self.button_data(picker))

    def test_upcloud_account_menu_has_shared_server_actions_without_primary_ip(self):
        acc = {"id": 1, "provider": "upcloud", "label": "edge", "proxy": None}
        data = self.button_data(self.bot.kb_account(acc))
        self.assertIn("srvs:1", data)
        self.assertIn("new:1", data)
        self.assertNotIn("hp:list:1:0", data)

    def test_upcloud_server_card_has_lifecycle_and_network_actions(self):
        acc = {"id": 1, "provider": "upcloud", "label": "edge"}
        server = {"id": "srv-uuid", "label": "node", "ip": "198.51.100.10",
                  "region": "fi-hel1", "plan": "1xCPU-1GB", "status": "started"}
        with patch.object(self.bot.st, "server_pass", return_value=None):
            text, markup = self.bot.build_server_card(1, "srv-uuid", acc, server, [])
        data = self.button_data(markup)
        self.assertIn("power", " ".join(data))
        self.assertTrue(any(x.startswith("ucip:") for x in data))
        self.assertIn("delsrv:1:srv-uuid", data)
        self.assertNotIn("hp:list:1:0", data)
        self.assertTrue(all(len(item.encode("utf-8")) <= 64 for item in data))

    def test_suspended_servers_mark_account_and_telegram_menu(self):
        import asyncio
        acc = {"id": 1, "provider": "linode", "label": "billing-account", "token": "secret"}
        provider = SimpleNamespace(list_servers=AsyncMock(return_value=[
            {"id": 1, "status": "billing_suspension"}]))
        with patch.object(self.bot.providers, "Provider", return_value=provider):
            _, status, detail = asyncio.run(self.bot.check_account(acc))
        self.assertEqual(status, "suspended")
        self.assertIn("Account suspended", detail)
        with patch.dict(self.bot.account_check_status, {1: status}), \
             patch.object(self.bot.st, "accounts", return_value=[acc]):
            markup = self.bot.kb_accounts()
        self.assertTrue(any('Suspended' in b.text for row in markup.inline_keyboard for b in row))

    def test_upcloud_account_check_does_not_report_fake_zero_billing(self):
        import asyncio
        provider = SimpleNamespace(whoami=AsyncMock(return_value="owner"),
                                   list_servers=AsyncMock(return_value=[]))
        acc = {"id": 1, "provider": "upcloud", "token": "secret"}
        with patch.object(self.bot.providers, "Provider", return_value=provider):
            result = asyncio.run(self.bot.check_account(acc))
        self.assertEqual(result[1], "ok")
        self.assertIn("موجود نیست", result[2])

    def test_upcloud_account_info_marks_unsupported_billing_fields_unknown(self):
        import asyncio
        from unittest.mock import AsyncMock
        provider = self.bot.providers.Provider({"provider": "upcloud", "token": "secret"})
        provider._req = AsyncMock(return_value={"account": {"username": "owner", "credits": "12.50"}})
        info = asyncio.run(provider.account_info())
        self.assertIsNone(info["balance"])
        self.assertIsNone(info["owed"])
        self.assertIsNone(info["pending_charges"])
        self.assertEqual(info["credit"], 12.5)

    def test_deployment_stores_only_provider_returned_upcloud_password(self):
        source = Path(self.bot.__file__).read_text(encoding="utf-8")
        self.assertIn('if acc["provider"] != "upcloud" and not server_password:', source)
        self.assertIn("images(data.get(\"region\"))", source)
        self.assertIn("ssh_keys=provider_keys", source)

    def test_upcloud_ip_callbacks_fit_telegram_limit_and_require_confirmation(self):
        import asyncio
        acc_id = 1234567890
        address = "2001:0db8:0000:0000:0000:ff00:0042:8329"
        acc = {"id": acc_id, "provider": "upcloud", "label": "edge"}
        provider = SimpleNamespace(
            upcloud_ip_addresses=AsyncMock(return_value=[{
                "address": address, "floating": True, "server_id": "uuid-123"}]),
            server=AsyncMock(return_value={"status": "started", "id": "uuid-123"}),
        )
        cb = SimpleNamespace(data=f"ucip:{acc_id}:uuid-123",
                             message=SimpleNamespace(edit_text=AsyncMock()), answer=AsyncMock())
        with patch.object(self.bot.st, "account", return_value=acc), \
                patch.object(self.bot.providers, "Provider", return_value=provider):
            asyncio.run(self.bot.upcloud_ip_manager(cb))
        markup = cb.message.edit_text.await_args.kwargs["reply_markup"]
        actions = self.button_data(markup)
        self.assertFalse(any(item.startswith("ucipnew:") for item in actions))
        self.assertTrue(any("خاموش کن" in item for item in [
            button.text for row in markup.inline_keyboard for button in row]))

        detach = next(item for item in actions if item.startswith("ucipdetach:"))
        confirm_cb = SimpleNamespace(data=detach,
                                     message=SimpleNamespace(edit_text=AsyncMock()), answer=AsyncMock())
        asyncio.run(self.bot.upcloud_ip_detach(confirm_cb))
        confirm_markup = confirm_cb.message.edit_text.await_args.kwargs["reply_markup"]
        confirmed = next(item for item in self.button_data(confirm_markup)
                         if item.startswith("ucipdetachok:"))
        self.assertLessEqual(len(confirmed.encode("utf-8")), 64)

    def test_upcloud_ip_creation_offer_is_stopped_state_only_and_confirmed(self):
        import asyncio
        acc_id = 123
        acc = {"id": acc_id, "provider": "upcloud", "label": "edge"}
        provider = SimpleNamespace(
            upcloud_ip_addresses=AsyncMock(return_value=[]),
            server=AsyncMock(return_value={"status": "stopped", "id": "srv-uuid"}),
        )
        cb = SimpleNamespace(data=f"ucip:{acc_id}:srv-uuid",
                             message=SimpleNamespace(edit_text=AsyncMock()), answer=AsyncMock())
        with patch.object(self.bot.st, "account", return_value=acc), \
                patch.object(self.bot.providers, "Provider", return_value=provider):
            asyncio.run(self.bot.upcloud_ip_manager(cb))
        markup = cb.message.edit_text.await_args.kwargs["reply_markup"]
        create = next(item for item in self.button_data(markup) if item.startswith("ucipnew:"))
        confirm_cb = SimpleNamespace(data=create,
                                     message=SimpleNamespace(edit_text=AsyncMock()), answer=AsyncMock())
        asyncio.run(self.bot.upcloud_ip_create(confirm_cb))
        confirm_markup = confirm_cb.message.edit_text.await_args.kwargs["reply_markup"]
        self.assertIn("ucipnewok:123:srv-uuid", self.button_data(confirm_markup))

        provider.create_upcloud_floating_ip = AsyncMock(return_value={"address": "198.51.100.2"})
        with patch.object(self.bot.st, "account", return_value=acc), \
                patch.object(self.bot.providers, "Provider", return_value=provider), \
                patch.object(self.bot, "schedule_account_server_ip_cache_refresh"):
            execute_cb = SimpleNamespace(
                data="ucipnewok:123:srv-uuid",
                message=SimpleNamespace(edit_text=AsyncMock()), answer=AsyncMock())
            asyncio.run(self.bot.upcloud_ip_create_execute(execute_cb))
        provider.create_upcloud_floating_ip.assert_awaited_once_with("srv-uuid", None, "keep")

    def test_upcloud_ip_control_hides_when_capability_is_disabled(self):
        acc = {"id": 1, "provider": "upcloud", "label": "edge"}
        server = {"id": "srv-uuid", "label": "node", "ip": "198.51.100.10",
                  "region": "fi-hel1", "plan": "1xCPU-1GB", "status": "started"}
        with patch.object(self.bot.providers, "provider_capabilities", return_value={"floating_ip": False}), \
                patch.object(self.bot.st, "server_pass", return_value=None):
            _, markup = self.bot.build_server_card(1, "srv-uuid", acc, server, [])
        self.assertFalse(any(item.startswith("ucip:") for item in self.button_data(markup)))


if __name__ == "__main__":
    unittest.main()
