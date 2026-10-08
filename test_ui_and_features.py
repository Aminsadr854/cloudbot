import json
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer

import control_service
import providers
from control_api import build_app
from store import Store, compute_ssh_fingerprint


class FakeHostingStore:
    def __init__(self):
        self._accounts = [
            {"id": 1, "label": "Hetzner-Prod", "provider": "hetzner", "token": "tok1", "proxy": None, "proxy_family": "default", "auto_backup": "disabled", "region": "", "created_at": 100},
            {"id": 2, "label": "Vultr-Edge", "provider": "vultr", "token": "tok2", "proxy": "socks5://user:pass@1.2.3.4:1080", "proxy_family": "ipv4", "auto_backup": "disabled", "region": "DE", "created_at": 200},
        ]
        self._ssh_keys = [
            {"id": 1, "name": "work-mac", "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlX04z9cR7Vp2H1lQ4vQ4j4d5m8x8k8x8k8x8k8x8k8 dev@local", "fingerprint": "SHA256:test", "created_at": 100}
        ]
        self._proxy_providers = [
            {"id": 1, "label": "Residential-DE", "family": "ipv4", "enabled": 1, "template": {"host": "proxy.example.com", "port": 8080, "scheme": "socks5"}},
        ]
        self._proxy_sessions = {
            1: [
                {"id": 10, "provider_id": 1, "session_id": "sess_1", "position": 1, "enabled": 1},
                {"id": 11, "provider_id": 1, "session_id": "sess_2", "position": 2, "enabled": 0},
            ],
        }
        self._proxy_bindings = {
            2: {"provider_id": 1, "country": "DE", "session_id": "sess_1"},
        }
        self._otps = {}
        self._server_passes = {}
        self.closed = False

    def create_login_otp(self, user_id, ttl=600):
        otp = "test-otp-123"
        self._otps[otp] = (user_id, 9999999999.0)
        return otp

    def verify_and_consume_login_otp(self, otp):
        if otp in self._otps:
            uid, exp = self._otps.pop(otp)
            return uid
        return None

    def accounts(self):
        return self._accounts

    def account(self, acc_id):
        for a in self._accounts:
            if a["id"] == acc_id:
                return a
        return None

    def add_account(self, label, provider, token, proxy=None, proxy_family="default", auto_backup="disabled", region=""):
        new_id = len(self._accounts) + 1
        acc = {"id": new_id, "label": label, "provider": provider, "token": token, "proxy": proxy, "proxy_family": proxy_family, "auto_backup": auto_backup, "region": (region or "").strip().upper(), "created_at": 300}
        self._accounts.append(acc)
        return new_id

    def delete_account(self, acc_id):
        before = len(self._accounts)
        self._accounts = [a for a in self._accounts if a["id"] != acc_id]
        return 1 if len(self._accounts) < before else 0

    def set_account_region(self, acc_id, region):
        for a in self._accounts:
            if a["id"] == acc_id:
                a["region"] = (region or "").strip().upper()
                return

    def set_proxy(self, acc_id, proxy, proxy_family="default", proxy_request=None):
        for a in self._accounts:
            if a["id"] == acc_id:
                a["proxy"] = proxy
                a["proxy_family"] = proxy_family
                return

    def allocate_proxy(self, provider_id, country, account_id, another=False):
        country_norm = (country or "").strip().upper()
        self._proxy_bindings[account_id] = {
            "provider_id": provider_id,
            "country": country_norm,
            "session_id": "sess_alloc_99",
        }
        return {
            "provider_id": provider_id,
            "country": country_norm,
            "session_id": "sess_alloc_99",
            "proxy": f"socks5://user_country_{country_norm}:pass@proxy.example.com:8080",
            "family": "ipv4",
            "token": "tok_alloc_99",
        }

    def proxy_availability(self, provider_id, country):
        return 7

    def proxy_providers(self):
        return [dict(p) for p in self._proxy_providers]

    def proxy_sessions(self, pid):
        return self._proxy_sessions.get(pid, [])

    def proxy_binding(self, acc_id):
        return self._proxy_bindings.get(acc_id)

    def add_proxy_sessions(self, pid, ids):
        if pid not in self._proxy_sessions:
            self._proxy_sessions[pid] = []
        added = 0
        existing = {s["session_id"] for s in self._proxy_sessions[pid]}
        for sid in ids:
            if sid not in existing:
                self._proxy_sessions[pid].append({
                    "id": len(self._proxy_sessions[pid]) + 1,
                    "provider_id": pid,
                    "session_id": sid,
                    "position": len(self._proxy_sessions[pid]) + 1,
                    "enabled": 1,
                })
                added += 1
        return added

    def add_proxy_provider(self, label, template, ids, family="default"):
        pid = len(self._proxy_providers) + 1
        self._proxy_providers.append({
            "id": pid,
            "label": label,
            "template": template if isinstance(template, dict) else {"host": "proxy.net", "port": 1080, "scheme": "socks5"},
            "family": family,
            "enabled": 1,
        })
        self._proxy_sessions[pid] = [{"id": i, "provider_id": pid, "session_id": sid, "enabled": 1} for i, sid in enumerate(ids, 1)]
        return pid

    def manage_proxy_provider(self, pid, action, value=None):
        if action == "delete":
            self._proxy_providers = [p for p in self._proxy_providers if p["id"] != pid]
            self._proxy_sessions.pop(pid, None)
            return True
        elif action == "toggle":
            for p in self._proxy_providers:
                if p["id"] == pid:
                    p["enabled"] = 0 if p.get("enabled", 1) else 1
                    return True
        return False

    def ssh_keys(self):
        return self._ssh_keys

    def ssh_key(self, key_id):
        for k in self._ssh_keys:
            if k["id"] == key_id:
                return k
        return None

    def add_ssh_key(self, name, public_key):
        new_id = len(self._ssh_keys) + 1
        fp = compute_ssh_fingerprint(public_key)
        self._ssh_keys.append({"id": new_id, "name": name, "public_key": public_key, "fingerprint": fp, "created_at": 300})
        return new_id

    def delete_ssh_key(self, key_id):
        before = len(self._ssh_keys)
        self._ssh_keys = [k for k in self._ssh_keys if k["id"] != key_id]
        return len(self._ssh_keys) < before

    def set_server_pass(self, acc_id, srv_id, password):
        self._server_passes[(acc_id, srv_id)] = password

    def server_pass(self, acc_id, srv_id):
        return self._server_passes.get((acc_id, srv_id), "vault-password-123")

    def delete_server_pass(self, acc_id, srv_id):
        self._server_passes.pop((acc_id, srv_id), None)

    def cf_token(self):
        return "fake-cf-token"

    def watch_cfg(self):
        return {"enabled": True, "auto_replace": False, "interval_minutes": 5}

    def watch_targets(self):
        return [{"id": 1, "label": "node-ir", "host": "1.2.3.4", "port": 443}]

    def watch_last(self):
        return {1: {"status": "OK", "latency": 45, "loss": 0}}

    def tunnels(self):
        return [{"id": 10, "kind": "gre", "iran_host": "10.0.0.1", "foreign_host": "20.0.0.1", "ports": "443,80", "created_at": 50}]

    def close(self):
        self.closed = True


class UiAndFeaturesTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = FakeHostingStore()
        self.token = "t" * 48
        self.client = TestClient(TestServer(build_app(token=self.token, store_factory=lambda: self.store)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()

    async def test_ui_static_routes_are_public(self):
        # Index should be served without auth
        res = await self.client.get("/")
        self.assertEqual(res.status, 200)
        text = await res.text()
        self.assertIn("Cloudbot Hosting Console", text)
        self.assertIn("Hetzner Cloud", text)
        self.assertIn("IP Management", text)

        # Style CSS
        css_res = await self.client.get("/ui/style.css")
        self.assertEqual(css_res.status, 200)
        css_text = await css_res.text()
        self.assertIn("app-header", css_text)

        # App JS
        js_res = await self.client.get("/ui/app.js")
        self.assertEqual(js_res.status, 200)
        js_text = await js_res.text()
        self.assertIn("Cloudbot Hosting Console", js_text)

    async def test_ssh_keys_crud_operations(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # List SSH keys
        res = await self.client.post("/v1/operations/ssh_keys", json={}, headers=headers)
        self.assertEqual(res.status, 200)
        data = await res.json()
        self.assertEqual(len(data["ssh_keys"]), 1)
        self.assertEqual(data["ssh_keys"][0]["name"], "work-mac")

        # Add SSH key
        new_key_body = {
            "name": "backup-key",
            "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlX04z9cR7Vp2H1lQ4vQ4j4d5m8x8k8x8k8x8k8x8k8 backup@remote",
            "sync_accounts": False
        }
        add_res = await self.client.post("/v1/operations/add_ssh_key", json=new_key_body, headers=headers)
        self.assertEqual(add_res.status, 200)
        add_data = await add_res.json()
        self.assertEqual(add_data["ssh_key"]["name"], "backup-key")
        self.assertTrue(add_data["ssh_key"]["fingerprint"].startswith("SHA256:"))

        # Delete SSH key
        del_res = await self.client.post("/v1/operations/delete_ssh_key", json={
            "key_id": add_data["ssh_key"]["id"],
            "confirm": "DELETE_SSH_KEY"
        }, headers=headers)
        self.assertEqual(del_res.status, 200)
        del_data = await del_res.json()
        self.assertTrue(del_data["deleted"])

    async def test_all_servers_multi_cloud_aggregation(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        mock_p1 = AsyncMock()
        mock_p1.list_servers.return_value = [{"id": 101, "name": "hz-srv-1", "ip": "1.1.1.1", "status": "running"}]
        mock_p1.hetzner_floating_ips.return_value = [{"id": 501, "ip": "188.245.1.1", "server": 101, "type": "ipv4"}]

        mock_p2 = AsyncMock()
        mock_p2.list_servers.return_value = [{"id": "vultr-202", "label": "vl-srv-2", "main_ip": "2.2.2.2", "status": "running"}]
        mock_p2.vultr_reserved_ips.return_value = []

        def get_mock_provider(acc):
            return mock_p1 if acc["provider"] == "hetzner" else mock_p2

        with patch.object(control_service, "Provider", side_effect=get_mock_provider):
            res = await self.client.post("/v1/operations/all_servers", json={}, headers=headers)
            self.assertEqual(res.status, 200)
            data = await res.json()
            servers = data["servers"]
            self.assertEqual(len(servers), 2)
            self.assertEqual(servers[0]["account_label"], "Hetzner-Prod")
            self.assertEqual(servers[0]["floating_ips"][0]["ip"], "188.245.1.1")
            self.assertEqual(servers[1]["account_label"], "Vultr-Edge")

    async def test_floating_ip_assignment_and_unassignment(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        mock_p = AsyncMock()
        mock_p.assign_hetzner_floating_ip.return_value = {"action": "assigned"}
        mock_p.unassign_hetzner_floating_ip.return_value = {"action": "unassigned"}

        with patch.object(control_service, "Provider", return_value=mock_p):
            # Assign
            res = await self.client.post("/v1/operations/assign_floating_ip", json={
                "account_id": 1, "floating_id": "501", "server_id": "101"
            }, headers=headers)
            self.assertEqual(res.status, 200)
            data = await res.json()
            self.assertTrue(data["assigned"])
            mock_p.assign_hetzner_floating_ip.assert_awaited_once_with("501", "101")

            # Unassign
            res_un = await self.client.post("/v1/operations/unassign_floating_ip", json={
                "account_id": 1, "floating_id": "501"
            }, headers=headers)
            self.assertEqual(res_un.status, 200)
            data_un = await res_un.json()
            self.assertTrue(data_un["unassigned"])
            mock_p.unassign_hetzner_floating_ip.assert_awaited_once_with("501")

    async def test_server_password_vault_retrieval(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        # Attempt without confirm
        denied = await self.client.post("/v1/operations/server_password", json={
            "account_id": 1, "server_id": "101"
        }, headers=headers)
        self.assertEqual(denied.status, 400)

        # With confirm
        allowed = await self.client.post("/v1/operations/server_password", json={
            "account_id": 1, "server_id": "101", "confirm": "SHOW_PASSWORD"
        }, headers=headers)
        self.assertEqual(allowed.status, 200)
        data = await allowed.json()
        self.assertEqual(data["password"], "vault-password-123")

    async def test_resolve_ssh_keys_across_providers(self):
        keys = [{"name": "dev-laptop", "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... dev@host"}]

        # Hetzner
        h_acc = {"id": 1, "label": "Hetzner 1", "provider": "hetzner", "token": "tok"}
        hp = providers.Provider(h_acc)
        with patch.object(hp, "create_hetzner_ssh_key", new_callable=AsyncMock) as m_hcreate:
            m_hcreate.return_value = {"id": 42, "name": "dev-laptop"}
            resolved = await hp.resolve_ssh_keys_for_instance(keys)
            self.assertEqual(resolved, [42])

        # Vultr
        v_acc = {"id": 2, "label": "Vultr 1", "provider": "vultr", "token": "tok"}
        vp = providers.Provider(v_acc)
        with patch.object(vp, "vultr_ssh_keys", new_callable=AsyncMock) as m_vlist:
            m_vlist.return_value = [{"id": "v-key-99", "name": "dev-laptop"}]
            resolved_v = await vp.resolve_ssh_keys_for_instance(keys)
            self.assertEqual(resolved_v, ["v-key-99"])

        # Linode
        l_acc = {"id": 3, "label": "Linode 1", "provider": "linode", "token": "tok"}
        lp = providers.Provider(l_acc)
        resolved_l = await lp.resolve_ssh_keys_for_instance(keys)
        self.assertEqual(resolved_l, ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... dev@host"])

    async def test_otp_login_flow(self):
        # Create OTP
        otp = self.store.create_login_otp(5665626083)
        with patch.dict("os.environ", {"CLOUDBOT_OWNER": "5665626083"}):
            res = await self.client.get(f"/login?otp={otp}", allow_redirects=False)
            self.assertEqual(res.status, 302)
            self.assertEqual(res.headers.get("Location"), "/")
            self.assertIn("cloudbot_token", res.cookies)
            self.assertEqual(res.cookies["cloudbot_token"].value, self.token)

            # Consuming again must fail with 403
            res2 = await self.client.get(f"/login?otp={otp}", allow_redirects=False)
            self.assertEqual(res2.status, 403)

    async def test_auth_me_endpoint(self):
        # Unauthenticated
        res = await self.client.get("/v1/auth/me")
        self.assertEqual(res.status, 200)
        data = await res.json()
        self.assertFalse(data["authenticated"])

        # Authenticated via Bearer
        res_auth = await self.client.get("/v1/auth/me", headers={"Authorization": f"Bearer {self.token}"})
        self.assertEqual(res_auth.status, 200)
        data_auth = await res_auth.json()
        self.assertTrue(data_auth["authenticated"])

    async def test_telegram_auth_verification(self):
        import hashlib
        import hmac
        import time

        bot_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
        owner_id = 5665626083
        auth_data = {
            "id": owner_id,
            "first_name": "Kia",
            "username": "realkia",
            "auth_date": int(time.time()),
        }
        # Build hash
        check_pairs = [f"{k}={auth_data[k]}" for k in sorted(auth_data.keys())]
        check_str = "\n".join(check_pairs)
        secret = hashlib.sha256(bot_token.encode("utf-8")).digest()
        auth_data["hash"] = hmac.new(secret, check_str.encode("utf-8"), hashlib.sha256).hexdigest()

        with patch.dict("os.environ", {"CLOUDBOT_TOKEN": bot_token, "CLOUDBOT_OWNER": str(owner_id)}):
            res = await self.client.post("/v1/auth/telegram", json=auth_data)
            self.assertEqual(res.status, 200)
            data = await res.json()
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["token"], self.token)
            self.assertIn("cloudbot_token", res.cookies)

    async def test_test_account_endpoint(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        mock_p = AsyncMock()
        mock_p.whoami.return_value = "hz-user-kia"
        mock_p.account_info.return_value = {"active_servers": 2, "monthly_runrate": 15.6}

        with patch.object(control_service, "Provider", return_value=mock_p):
            res = await self.client.post("/v1/operations/test_account", json={"account_id": 1}, headers=headers)
            self.assertEqual(res.status, 200)
            data = await res.json()
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["identity"], "hz-user-kia")
            self.assertEqual(data["info"]["monthly_runrate"], 15.6)
            self.assertIn("latency_ms", data)

    async def test_set_account_proxy_endpoint(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        res = await self.client.post("/v1/operations/set_account_proxy", json={
            "account_id": 1,
            "proxy": "socks5://user:pass@1.2.3.4:1080",
            "proxy_family": "ipv4"
        }, headers=headers)
        self.assertEqual(res.status, 200)
        data = await res.json()
        self.assertTrue(data["updated"])
        self.assertTrue(data["account"]["has_proxy"])
        self.assertEqual(data["account"]["proxy_family"], "ipv4")

        # Clear proxy
        res_clear = await self.client.post("/v1/operations/set_account_proxy", json={
            "account_id": 1,
            "proxy": "",
            "proxy_family": "default"
        }, headers=headers)
        self.assertEqual(res_clear.status, 200)
        data_clear = await res_clear.json()
        self.assertFalse(data_clear["account"]["has_proxy"])

    async def test_proxy_providers_management(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # List proxy providers
        res = await self.client.post("/v1/operations/proxy_providers", json={}, headers=headers)
        self.assertEqual(res.status, 200)
        data = await res.json()
        providers_list = data["providers"]
        self.assertEqual(len(providers_list), 1)
        self.assertEqual(providers_list[0]["label"], "Residential-DE")
        self.assertEqual(providers_list[0]["total_sessions"], 2)
        self.assertEqual(providers_list[0]["active_sessions"], 1)
        self.assertEqual(len(providers_list[0]["bound_accounts"]), 1)
        self.assertEqual(providers_list[0]["bound_accounts"][0]["account_label"], "Vultr-Edge")

        # Add proxy provider
        add_res = await self.client.post("/v1/operations/add_proxy_provider", json={
            "label": "Mobile-US",
            "template": "socks5://user_{session}:pass@pool.us.com:9000",
            "session_ids": "s1\ns2\ns3\ns4\ns5",
            "family": "ipv4"
        }, headers=headers)
        self.assertEqual(add_res.status, 200)
        add_data = await add_res.json()
        self.assertEqual(add_data["label"], "Mobile-US")
        self.assertEqual(add_data["sessions_count"], 5)
        new_pid = add_data["id"]

        # Delete proxy provider
        del_res = await self.client.post("/v1/operations/delete_proxy_provider", json={
            "provider_id": new_pid,
            "confirm": "DELETE_PROXY_PROVIDER"
        }, headers=headers)
        self.assertEqual(del_res.status, 200)
        del_data = await del_res.json()
        self.assertTrue(del_data["deleted"])

    async def test_test_proxy_endpoint(self):
        from unittest.mock import MagicMock
        headers = {"Authorization": f"Bearer {self.token}"}
        # Test proxy with mock
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"ip": "198.51.100.22"})

        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_response
        mock_cm.__aexit__.return_value = None

        mock_session = MagicMock()
        mock_session.get.return_value = mock_cm
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None

        with patch("aiohttp.ClientSession", return_value=mock_session):
            res = await self.client.post("/v1/operations/test_proxy", json={
                "proxy": "http://user:pass@198.51.100.22:8080"
            }, headers=headers)
            self.assertEqual(res.status, 200)
            data = await res.json()
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["ip"], "198.51.100.22")
            self.assertIn("latency_ms", data)

    async def test_set_account_region_and_custom_proxy(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # 1. Update region directly
        res = await self.client.post("/v1/operations/set_account_region", json={
            "account_id": 1,
            "region": "nl"
        }, headers=headers)
        self.assertEqual(res.status, 200)
        data = await res.json()
        self.assertTrue(data["updated"])
        self.assertEqual(data["account"]["region"], "NL")

        # 1b. Test UAE normalization to AE
        res_uae = await self.client.post("/v1/operations/set_account_region", json={
            "account_id": 1,
            "region": "uae"
        }, headers=headers)
        self.assertEqual(res_uae.status, 200)
        data_uae = await res_uae.json()
        self.assertEqual(data_uae["account"]["region"], "AE")

        # 2. Update custom proxy with region
        res2 = await self.client.post("/v1/operations/set_account_proxy", json={
            "account_id": 1,
            "proxy": "socks5://cust_user:cust_pass@192.0.2.1:1080",
            "proxy_family": "ipv4",
            "region": "se"
        }, headers=headers)
        self.assertEqual(res2.status, 200)
        data2 = await res2.json()
        self.assertTrue(data2["updated"])
        self.assertEqual(data2["account"]["region"], "SE")
        self.assertTrue(data2["account"]["has_proxy"])
        self.assertIn("192.0.2.1", data2["account"]["proxy_masked"])

        # 3. Verify accounts list returns public region and masked proxy
        res3 = await self.client.post("/v1/operations/accounts", json={}, headers=headers)
        self.assertEqual(res3.status, 200)
        data3 = await res3.json()
        acc1 = next(a for a in data3["accounts"] if a["id"] == 1)
        self.assertEqual(acc1["region"], "SE")
        self.assertTrue(acc1["has_proxy"])

    async def test_allocate_account_proxy_and_availability(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # 1. Check availability
        avail_res = await self.client.post("/v1/operations/proxy_availability", json={
            "provider_id": 1,
            "country": "de"
        }, headers=headers)
        self.assertEqual(avail_res.status, 200)
        avail_data = await avail_res.json()
        self.assertEqual(avail_data["provider_id"], 1)
        self.assertEqual(avail_data["country"], "DE")
        self.assertEqual(avail_data["available"], 7)

        # 2. Allocate proxy session from pool to account
        alloc_res = await self.client.post("/v1/operations/allocate_account_proxy", json={
            "account_id": 1,
            "provider_id": 1,
            "country": "de"
        }, headers=headers)
        self.assertEqual(alloc_res.status, 200)
        alloc_data = await alloc_res.json()
        self.assertTrue(alloc_data["updated"])
        self.assertEqual(alloc_data["account"]["region"], "DE")
        self.assertIsNotNone(alloc_data["account"]["binding"])
        self.assertEqual(alloc_data["account"]["binding"]["session_id"], "sess_alloc_99")
        self.assertTrue(alloc_data["account"]["has_proxy"])

    async def test_page_routes_serve_ui(self):
        # Multi-page URLs should serve the web application without requiring auth tokens
        for route in ["/overview", "/accounts", "/proxies", "/hetzner", "/vultr", "/linode", "/compute", "/ips", "/ssh", "/dns", "/watchdog"]:
            res = await self.client.get(route)
            self.assertEqual(res.status, 200, f"Route {route} failed")
            body = await res.text()
            self.assertIn("Cloudbot", body)

    async def test_bulk_parse_and_add_proxy_sessions(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        raw_input = """
        eu.swiftproxy.net:7878:user_country_MY_sid_27369618_time_10:acou234KD
        eu.swiftproxy.net:7878:user_country_MY_sid_27369619_time_10:acou234KD
        socks5://user-ssid-xyz999:pass@proxy.example.com:1080
        sess_standalone_44
        """

        # 1. Test parse_proxy_sessions
        parse_res = await self.client.post("/v1/operations/parse_proxy_sessions", json={
            "raw_text": raw_input
        }, headers=headers)
        self.assertEqual(parse_res.status, 200)
        parse_data = await parse_res.json()
        self.assertEqual(parse_data["count"], 4)
        self.assertIn("27369618", parse_data["session_ids"])
        self.assertIn("27369619", parse_data["session_ids"])
        self.assertIn("xyz999", parse_data["session_ids"])
        self.assertIn("sess_standalone_44", parse_data["session_ids"])

        # 2. Test add_proxy_sessions
        add_res = await self.client.post("/v1/operations/add_proxy_sessions", json={
            "provider_id": 1,
            "raw_text": raw_input
        }, headers=headers)
        self.assertEqual(add_res.status, 200)
        add_data = await add_res.json()
        self.assertEqual(add_data["added"], 4)
        self.assertGreaterEqual(add_data["total_sessions"], 4)

    async def test_numbered_proxy_list_session_extraction(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        numbered_input = """
1
niceproxy.io:17521:accounts1_k5ub-country-AF-ssid-FLPd7d6l0X:accpas2
2
niceproxy.io:17521:accounts1_k5ub-country-AF-ssid-fK8NLFu5W3:accpas2
3
niceproxy.io:17521:accounts1_k5ub-country-AF-ssid-JySrhHa9NT:accpas2
4
niceproxy.io:17521:accounts1_k5ub-country-AF-ssid-Q2JzZBdagY:accpas2
5
niceproxy.io:17521:accounts1_k5ub-country-AF-ssid-JcVtnUPMVN:accpas2
        """
        parse_res = await self.client.post("/v1/operations/parse_proxy_sessions", json={
            "raw_text": numbered_input,
            "provider_id": 1
        }, headers=headers)
        self.assertEqual(parse_res.status, 200)
        parse_data = await parse_res.json()
        self.assertEqual(parse_data["count"], 5)
        self.assertEqual(parse_data["session_ids"], [
            "FLPd7d6l0X", "fK8NLFu5W3", "JySrhHa9NT", "Q2JzZBdagY", "JcVtnUPMVN"
        ])

        add_res = await self.client.post("/v1/operations/add_proxy_sessions", json={
            "provider_id": 1,
            "raw_text": numbered_input
        }, headers=headers)
        self.assertEqual(add_res.status, 200)
        add_data = await add_res.json()
        self.assertEqual(add_data["added"], 5)
        self.assertEqual(add_data["extracted"], [
            "FLPd7d6l0X", "fK8NLFu5W3", "JySrhHa9NT", "Q2JzZBdagY", "JcVtnUPMVN"
        ])


    async def test_auto_heal_proxies(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Mock whoami so account with old broken proxy (1.2.3.4) fails with 403, and succeeds once allocated new proxy
        async def fake_whoami(self):
            if "1.2.3.4" in (self.proxy or ""):
                raise Exception("HTTP 403 Forbidden - Proxy authentication failed")
            return "ok"

        with patch.object(providers.Provider, "whoami", new=fake_whoami):
            res = await self.client.post("/v1/operations/auto_heal_proxies", json={}, headers=headers)
            self.assertEqual(res.status, 200)
            data = await res.json()
            self.assertEqual(data["healed_count"], 1)
            self.assertEqual(data["healed"][0]["id"], 2)
            self.assertEqual(data["healed"][0]["country"], "DE")

    def test_store_data_cache_methods(self):
        import tempfile
        import os
        from cryptography.fernet import Fernet
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf, tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
            db_path = tf.name
            key_path = kf.name
            kf.write(Fernet.generate_key())
            kf.flush()
        try:
            store = Store(db_path, key_path=key_path)
            self.assertIsNone(store.get_cache("test_key"))
            self.assertEqual(store.get_cache("test_key", default={"val": 1}), {"val": 1})

            store.set_cache("test_key", {"servers": [{"id": 1, "name": "alpha"}]})
            cached = store.get_cache("test_key")
            self.assertIsNotNone(cached)
            self.assertEqual(cached["servers"][0]["name"], "alpha")

            # Update cache
            store.set_cache("test_key", {"servers": [{"id": 2, "name": "beta"}]})
            cached = store.get_cache("test_key")
            self.assertEqual(cached["servers"][0]["name"], "beta")

            # Delete cache
            store.delete_cache("test_key")
            self.assertIsNone(store.get_cache("test_key"))
            store.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(key_path):
                os.remove(key_path)

    async def test_control_service_cache_and_invalidation(self):
        import tempfile
        import os
        from cryptography.fernet import Fernet
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf, tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
            db_path = tf.name
            key_path = kf.name
            kf.write(Fernet.generate_key())
            kf.flush()
        try:
            store = Store(db_path, key_path=key_path)
            store.add_account("Test-Hetzner", "hetzner", "fake-token", region="DE")
            acc = store.accounts()[0]

            # 1. Seed cache
            store.set_cache("all_servers", {"servers": [{"id": 99, "name": "cached-node"}], "account_errors": {}})
            # Call all_servers without refresh -> should return cached immediately
            res = await control_service.execute("all_servers", {}, store)
            self.assertEqual(len(res["servers"]), 1)
            self.assertEqual(res["servers"][0]["name"], "cached-node")

            # 2. Test cache invalidation on delete_account
            await control_service.execute("delete_account", {"account_id": acc["id"], "confirm": "DELETE_ACCOUNT"}, store)
            self.assertIsNone(store.get_cache("all_servers"))
            self.assertIsNone(store.get_cache("all_floating_ips"))
            self.assertIsNone(store.get_cache("all_billing"))
            store.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(key_path):
                os.remove(key_path)

    async def test_add_account_with_proxy_provider(self):
        import tempfile
        import os
        from cryptography.fernet import Fernet
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf, tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
            db_path = tf.name
            key_path = kf.name
            kf.write(Fernet.generate_key())
            kf.flush()
        try:
            store = Store(db_path, key_path=key_path)
            pid = store.add_proxy_provider("TestPool", "http://user-country-{country}-sess-{session}:pass@1.2.3.4:8080", ["s1", "s2"])
            
            # Check availability with auto provider
            avail = await control_service.execute("proxy_availability", {"country": "DE", "provider_id": "auto"}, store)
            self.assertEqual(avail["available"], 2)

            # Add account with proxy_provider_id="auto"
            res = await control_service.execute("add_account", {
                "label": "acc-pool",
                "provider": "hetzner",
                "token": "tok-12345678",
                "region": "DE",
                "proxy_provider_id": "auto"
            }, store)
            self.assertEqual(res["region"], "DE")
            self.assertIn("allocated_proxy", res)
            self.assertEqual(res["allocated_proxy"]["country"], "DE")

            acc = store.account(res["id"])
            self.assertIsNotNone(acc["proxy"])
            self.assertIn("country-DE", acc["proxy"])
            self.assertIn("sess-s1", acc["proxy"])

            # Check availability decreased
            avail2 = await control_service.execute("proxy_availability", {"country": "DE", "provider_id": "auto"}, store)
            self.assertEqual(avail2["available"], 1)

            store.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(key_path):
                os.remove(key_path)

    async def test_apply_linode_promo_code(self):
        import tempfile
        import os
        from unittest.mock import patch, AsyncMock
        from cryptography.fernet import Fernet
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf, tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
            db_path = tf.name
            key_path = kf.name
            kf.write(Fernet.generate_key())
            kf.flush()
        try:
            store = Store(db_path, key_path=key_path)
            store.add_account("linode-acc", "linode", "tok-123", region="US")
            store.add_account("hetzner-acc", "hetzner", "tok-456", region="DE")
            l_acc = store.accounts()[0]
            h_acc = store.accounts()[1]

            # 1. Non-linode rejected
            with self.assertRaises(control_service.InputError):
                await control_service.execute("apply_promo_code", {"account_id": h_acc["id"], "promo_code": "DOCS100"}, store)

            # 2. Linode promo applied
            with patch.object(providers.Provider, "apply_linode_promo_code", new_callable=AsyncMock) as mock_promo:
                mock_promo.return_value = {"credit_remaining": "100.00", "summary": "100 USD Credit"}
                res = await control_service.execute("apply_promo_code", {"account_id": l_acc["id"], "promo_code": "DOCS100"}, store)
                self.assertTrue(res["applied"])
                self.assertEqual(res["promo_code"], "DOCS100")
                self.assertEqual(res["promotion"]["credit_remaining"], "100.00")
                mock_promo.assert_called_once_with("DOCS100")

            store.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(key_path):
                os.remove(key_path)

    async def test_delete_floating_ip_without_server_id(self):
        # Verify that delete_floating_ip does NOT require server_id
        headers = {"Authorization": f"Bearer {self.token}"}
        with patch.object(providers.Provider, "delete_hetzner_floating_ip", new_callable=AsyncMock) as mock_del:
            mock_del.return_value = True
            res = await self.client.post("/v1/operations/delete_floating_ip", json={
                "account_id": 1,
                "floating_id": "fip-12345",
                "confirm": "DELETE_FLOATING_IP"
            }, headers=headers)
            self.assertEqual(res.status, 200)
            data = await res.json()
            self.assertTrue(data.get("deleted"))
            self.assertEqual(data.get("floating_id"), "fip-12345")
            mock_del.assert_called_once_with("fip-12345")

    async def test_plans_and_images_caching(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        with patch.object(providers.Provider, "plans", new_callable=AsyncMock) as mock_plans, \
             patch.object(providers.Provider, "images", new_callable=AsyncMock) as mock_imgs:
            mock_plans.return_value = [("cx22", "CX22 2vCPU 4GB")]
            mock_imgs.return_value = [("ubuntu-24.04", "Ubuntu 24.04")]

            # First call fetches from provider
            res1 = await self.client.post("/v1/operations/plans", json={
                "account_id": 1,
                "region": "fsn1"
            }, headers=headers)
            self.assertEqual(res1.status, 200)
            data1 = await res1.json()
            self.assertEqual(len(data1["plans"]), 1)
            self.assertEqual(mock_plans.call_count, 1)

            # Second call hits cache (mock_plans should NOT be called again)
            res2 = await self.client.post("/v1/operations/plans", json={
                "account_id": 1,
                "region": "fsn1"
            }, headers=headers)
            self.assertEqual(res2.status, 200)
            data2 = await res2.json()
            self.assertEqual(data2["plans"], data1["plans"])
            self.assertEqual(mock_plans.call_count, 1)

            # First images call
            img_res1 = await self.client.post("/v1/operations/images", json={
                "account_id": 1
            }, headers=headers)
            self.assertEqual(img_res1.status, 200)
            self.assertEqual(mock_imgs.call_count, 1)

            # Second images call hits cache
            img_res2 = await self.client.post("/v1/operations/images", json={
                "account_id": 1
            }, headers=headers)
            self.assertEqual(img_res2.status, 200)
            self.assertEqual(mock_imgs.call_count, 1)

    async def test_create_server_disables_ipv6_by_default(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        with patch.object(providers.Provider, "plans", new_callable=AsyncMock) as mock_plans, \
             patch.object(providers.Provider, "create_server", new_callable=AsyncMock) as mock_create:
            mock_plans.return_value = [("cx22", "CX22")]
            mock_create.return_value = {
                "id": 1001, "name": "test-srv", "ip": "1.2.3.4", "region": "fsn1",
                "country": "DE", "plan": "cx22", "root_password": "generated-pwd"
            }

            res = await self.client.post("/v1/operations/create_server", json={
                "account_id": 1,
                "region": "fsn1",
                "plan": "cx22",
                "image": "ubuntu-24.04",
                "name": "test-srv",
                "count": 1,
                "confirm": "CREATE_SERVER"
            }, headers=headers)
            self.assertEqual(res.status, 200)
            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            self.assertIn("enable_ipv6", call_kwargs)
            self.assertFalse(call_kwargs["enable_ipv6"])

    async def test_create_server_enables_ipv6_when_requested(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        with patch.object(providers.Provider, "plans", new_callable=AsyncMock) as mock_plans, \
             patch.object(providers.Provider, "create_server", new_callable=AsyncMock) as mock_create:
            mock_plans.return_value = [("cx22", "CX22")]
            mock_create.return_value = {
                "id": 1002, "name": "test-srv-v6", "ip": "1.2.3.4", "region": "fsn1",
                "country": "DE", "plan": "cx22", "root_password": "generated-pwd"
            }

            res = await self.client.post("/v1/operations/create_server", json={
                "account_id": 1,
                "region": "fsn1",
                "plan": "cx22",
                "image": "ubuntu-24.04",
                "name": "test-srv-v6",
                "count": 1,
                "enable_ipv6": True,
                "confirm": "CREATE_SERVER"
            }, headers=headers)
            self.assertEqual(res.status, 200)
            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            self.assertTrue(call_kwargs["enable_ipv6"])

    def test_ui_contains_bulk_actions_ipv6_and_ip_separation(self):
        with open("projects/cloudbot/ui/index.html") as f:
            html = f.read()
        with open("projects/cloudbot/ui/app.js") as f:
            js = f.read()

        # 1. Multi-server selection & deletion toolbar and controls
        self.assertIn("compute-bulk-bar", html)
        self.assertIn("cb-all-compute-select-all", html)
        self.assertIn("deleteSelectedServers", js)
        self.assertIn("toggleSelectAllInView", js)
        self.assertIn("toggleServerSelection", js)
        self.assertIn("clearServerSelection", js)

        # 2. Hetzner IPv6 checkbox (disabled by default)
        self.assertIn("deploy-hetzner-options", html)
        self.assertIn("deploy-enable-ipv6", html)
        self.assertIn("deploy-enable-ipv6", js)

        # 3. Per-account IP management pills and filtering
        self.assertIn("ips-account-filter-pills", html)
        self.assertIn("setIpsAccountFilter", js)
        self.assertIn("ipsAccountFilter", js)

        # 4. Separate Hetzner Floating IPs and Primary IPs
        self.assertIn("ips-floating-section", html)
        self.assertIn("hetzner-primary-ips-wrapper", html)
        self.assertIn("Hetzner Primary IPs", js)
        self.assertIn("Hetzner Floating IPs", js)








