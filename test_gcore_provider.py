import asyncio
import base64
import unittest
from unittest.mock import patch

import providers


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class GcoreProviderTests(unittest.TestCase):
    def provider(self, token="tok123"):
        return providers.Provider({"id": 1, "provider": "gcore", "token": token})

    def fake(self, calls, routes):
        async def _req(self_, method, path, **kw):
            calls.append((method, path, kw))
            for (m, prefix), value in routes.items():
                if m == method and path.startswith(prefix):
                    return value
            raise AssertionError(f"unexpected {method} {path}")
        return patch.object(providers.Provider, "_req", _req)

    def test_credentials(self):
        self.assertEqual(self.provider()._gcore_credentials(), {"token": "tok123", "project_id": None})
        self.assertEqual(self.provider("tok:42")._gcore_credentials()["project_id"], 42)
        self.assertEqual(self.provider('{"token":"t","project_id":"7"}')._gcore_credentials()["project_id"], 7)
        with self.assertRaises(providers.ProviderError):
            self.provider("tok:abc")._gcore_credentials()

    def test_open_firewall_adds_missing_rules_only(self):
        calls = []
        group = {"id": "g1", "name": "default", "security_group_rules": [
            {"direction": "ingress", "ethertype": "IPv4", "protocol": None,
             "port_range_min": None, "remote_ip_prefix": "0.0.0.0/0"},
            {"direction": "ingress", "ethertype": "IPv4", "protocol": "tcp",
             "port_range_min": 22, "remote_ip_prefix": None}]}
        routes = {("GET", "/v1/projects"): {"results": [{"id": 5, "is_default": True}]},
                  ("GET", "/v1/securitygroups/5/26"): {"results": [group]},
                  ("POST", "/v1/securitygroups/5/26/g1/rules"): {}}
        with self.fake(calls, routes):
            out = run(self.provider().gcore_open_firewall(26))
        self.assertEqual(out["regions"][0]["added"], ["IPv6"])
        posts = [c for c in calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][2]["json"]["remote_ip_prefix"], "::/0")
        self.assertEqual(posts[0][2]["json"]["protocol"], "any")

    def test_split_id(self):
        self.assertEqual(providers.Provider._gcore_split_id("76:abc-def"), (76, "abc-def"))
        with self.assertRaises(providers.ProviderError):
            providers.Provider._gcore_split_id("abc")

    def test_list_servers_and_project_discovery(self):
        calls = []
        routes = {
            ("GET", "/v1/projects"): {"results": [{"id": 9, "is_default": True}]},
            ("GET", "/v1/regions"): {"results": [{"id": 76, "state": "ACTIVE", "country": "LU", "display_name": "Luxembourg"}]},
            ("GET", "/v1/instances/9/76"): {"results": [{
                "instance_id": "u1", "instance_name": "n1", "status": "ACTIVE",
                "flavor": {"flavor_name": "g1-standard-1-2", "vcpus": 1, "ram": 2048},
                "addresses": {"ext": [{"addr": "45.9.9.9", "type": "fixed"},
                                      {"addr": "10.0.0.4", "type": "fixed"}]}}]},
        }
        with self.fake(calls, routes):
            out = run(self.provider().list_servers())
        self.assertEqual(out[0]["id"], "76:u1")
        self.assertEqual(out[0]["ip"], "45.9.9.9")
        self.assertEqual(out[0]["ips"], ["45.9.9.9"])
        self.assertEqual(out[0]["plan"], "g1-standard-1-2")

    def test_create_delete_power(self):
        calls = []
        routes = {
            ("GET", "/v1/images/9/76/img1"): {"min_disk": 5},
            ("GET", "/v1/securitygroups/9/76"): {"results": []},
            ("POST", "/v2/instances/9/76"): {"tasks": ["t1"]},
            ("GET", "/v1/tasks/t1"): {"state": "FINISHED", "created_resources": {"instances": ["u1"]}},
            ("GET", "/v1/instances/9/76/u1"): {"instance_id": "u1", "instance_name": "n", "status": "ACTIVE",
                                               "volumes": [{"id": "v1"}], "addresses": {}},
            ("DELETE", "/v1/instances/9/76/u1"): {"tasks": ["t2"]},
            ("POST", "/v1/instances/9/76/u1/"): {"tasks": ["t3"]},
        }
        p = self.provider("tok:9")
        with self.fake(calls, routes):
            srv = run(p.create_server("n", "76", "g1-standard-1-2", "img1", "pw", ssh_keys=["ssh-ed25519 AAA k"]))
            self.assertEqual(srv["id"], "76:u1")
            body = next(c[2]["json"] for c in calls if c[0] == "POST" and c[1].startswith("/v2/"))
            self.assertEqual(body["volumes"][0]["size"], 10)
            self.assertNotIn("password", body)
            ud = base64.b64decode(body["user_data"]).decode()
            self.assertIn("root:pw", ud)
            self.assertIn("ssh-ed25519 AAA k", ud)
            run(p.delete_server("76:u1"))
            self.assertTrue(any(c[0] == "DELETE" and "volumes=v1" in c[1] for c in calls))
            run(p.power_server("76:u1", "reboot"))
            self.assertTrue(any(c[1].endswith("/u1/reboot") for c in calls))
            with self.assertRaises(providers.ProviderError):
                run(p.power_server("76:u1", "nope"))


if __name__ == "__main__":
    unittest.main()
