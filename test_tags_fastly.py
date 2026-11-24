import os
import tempfile
import unittest
from unittest.mock import patch

import control_service
import providers


class TagTests(unittest.TestCase):
    def test_normalize_tags(self):
        n = control_service._normalize_tags
        self.assertEqual(n(" Prod, client X ,prod,"), ["prod", "client-x"])
        self.assertEqual(n(["A", "b"]), ["a", "b"])
        self.assertEqual(n(None), [])
        with self.assertRaises(control_service.InputError):
            n("x" * 25)
        with self.assertRaises(control_service.InputError):
            n(",".join(str(i) for i in range(9)))
        with self.assertRaises(control_service.InputError):
            n("bad$tag")

    def test_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["CLOUDBOT_DB"] = f"{d}/c.db"
            os.environ["CLOUDBOT_KEY"] = f"{d}/k.key"
            import store
            st = store.Store()
            acc = st.add_account("a", "fastly", "tok", tags=["prod", "cdn"])
            self.assertEqual(st.account(acc)["tags"], ["prod", "cdn"])
            st.set_account_tags(acc, ["x"])
            self.assertEqual(st.account(acc)["tags"], ["x"])
            st.set_account_tags(acc, [])
            self.assertEqual(st.account(acc)["tags"], [])
            self.assertEqual(control_service._account_public(st.account(acc), st)["tags"], [])


class FastlyTests(unittest.IsolatedAsyncioTestCase):
    def acct(self):
        return {"id": 1, "provider": "fastly", "token": "secret-tok", "proxy": None}

    async def test_services_and_identity(self):
        calls = []

        async def fake_req(self, method, path, **kw):
            calls.append(path)
            if path.startswith("/service"):
                return [{"id": "b", "name": "Beta", "versions": [{"number": 1}, {"number": 2, "active": True}]},
                        {"id": "a", "name": "alpha", "versions": []}]
            if path == "/tokens/self":
                return {"name": "main", "scope": "global"}
            return {"name": "Acme"}

        with patch.object(providers.Provider, "_req", fake_req):
            p = providers.Provider(self.acct())
            self.assertEqual(await p.whoami(), "Acme")
            svc = await p.fastly_services()
            self.assertEqual([s["name"] for s in svc], ["alpha", "Beta"])
            self.assertEqual(svc[1]["active_version"], 2)
            info = await p.account_info()
            self.assertEqual(info["services_count"], 2)
            self.assertEqual(await p.list_servers(), [])

    async def test_edge_check_states(self):
        async def fake_req(self, method, path, **kw):
            if path.startswith("/service?"):
                return [{"id": "a", "name": "act", "versions": [{"number": 1, "active": True}]},
                        {"id": "b", "name": "off", "versions": [{"number": 1}]}]
            return [{"name": "x.global.ssl.fastly.net"}]

        async def check(probe):
            with patch.object(providers.Provider, "_req", fake_req), \
                 patch.object(providers, "fastly_edge_probe", probe):
                return await providers.Provider(self.acct()).fastly_edge_check()

        self.assertEqual((await check(lambda d: ("ok", 200)))["state"], "ok")
        self.assertEqual((await check(lambda d: ("dead", 500)))["state"], "dead")
        self.assertEqual((await check(lambda d: ("unknown", None)))["state"], "inconclusive")

        async def none_active(self, method, path, **kw):
            return [{"id": "b", "name": "off", "versions": [{"number": 1}]}]
        with patch.object(providers.Provider, "_req", none_active):
            r = await providers.Provider(self.acct()).fastly_edge_check()
        self.assertEqual((r["state"], r["active"]), ("unconfigured", 0))

    async def test_canary_create_and_state(self):
        calls = []

        async def fake_req(self, method, path, **kw):
            calls.append((method, path))
            if path.startswith("/service?"):
                return []
            if path == "/service":
                return {"id": "svc1"}
            return {}

        with patch.object(providers.Provider, "_req", fake_req):
            r = await providers.Provider(self.acct()).fastly_ensure_canary()
        self.assertTrue(r["created"] and r["domain"].startswith("cbcanary-"))
        self.assertIn(("PUT", "/service/svc1/version/1/activate"), calls)

        async def with_canary(self, method, path, **kw):
            if path.startswith("/service?"):
                return [{"id": "c", "name": "cloudbot-canary", "versions": [{"number": 1, "active": True}]}]
            return [{"name": "cbcanary-x.global.ssl.fastly.net"}]
        with patch.object(providers.Provider, "_req", with_canary), \
             patch.object(providers, "fastly_edge_probe", lambda d: ("dead", 500)):
            # no updated_at => cannot prove it is young, so the dead reading stands
            self.assertEqual((await providers.Provider(self.acct()).fastly_canary_state())[0], "dead")
        with patch.object(providers.Provider, "_req", with_canary), \
             patch.object(providers, "fastly_edge_probe", lambda d: ("dead", 500)):
            self.assertEqual((await providers.Provider(self.acct()).fastly_canary_state())[0], "dead")

        async def without(self, method, path, **kw):
            return []
        with patch.object(providers.Provider, "_req", without):
            self.assertIsNone(await providers.Provider(self.acct()).fastly_canary_state())

    def test_no_active_service_is_not_suspended(self):
        self.assertEqual(providers.account_suspension([], {"services_count": 3, "active_services": 0}), {})

    async def test_header_and_base(self):
        p = providers.Provider(self.acct())
        self.assertEqual(p._base(), "https://api.fastly.com")
        self.assertFalse(providers.provider_capabilities("fastly")["server_lifecycle"])


if __name__ == "__main__":
    unittest.main()
