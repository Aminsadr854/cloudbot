import asyncio
import os
import tempfile
import unittest


class FakeProv:
    def __init__(self, provider, replies, acct=7):
        self.provider, self.replies, self.account = provider, replies, {"id": acct}

    async def _req(self, method, path, **kw):
        return self.replies[path.split("?")[0]]


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        os.environ["CLOUDBOT_TRAFFIC_DB"] = f"{self.d.name}/t.db"
        import traffic
        self.t = traffic

    def tearDown(self):
        os.environ.pop("CLOUDBOT_TRAFFIC_DB", None)
        self.d.cleanup()

    def test_counter_reset_and_kept_after_delete(self):
        for out in (1000, 5000, 300):  # last value = monthly reset
            self.t.record("hetzner:1", 7, "n1", counter=(out, 10))
        tot = self.t.totals(7, "hetzner")
        self.assertEqual((tot["out"], tot["in"], tot["items"]), (5300, 10, 1))

    def test_buckets_replace(self):
        self.t.record("vultr:1", 7, "x", buckets={"2026-11-01": (100, 5), "2026-11-02": (50, 1)})
        self.t.record("vultr:1", 7, "x", buckets={"2026-11-02": (70, 2), "2026-11-03": (10, 0)})
        tot = self.t.totals(7, "vultr")
        self.assertEqual((tot["out"], tot["in"]), (180, 7))

    def test_sample_server_and_final_read(self):
        p = FakeProv("hetzner", {"/servers/9": {"server": {"outgoing_traffic": 42, "ingoing_traffic": 3}}})
        asyncio.run(self.t.sample_before_delete(p, 9))
        tot = self.t.totals(7, "hetzner")
        self.assertEqual((tot["out"], tot["in"]), (42, 3))

    def test_fastly_account_figure_wins(self):
        p = FakeProv("fastly", {"/stats/aggregate": {"data": [{"start_time": 1761955200, "bandwidth": 900}]},
                                "/stats/service/s1": {"data": [{"start_time": 1761955200, "bandwidth": 400}]}})

        async def services():
            return [{"id": "s1", "name": "svc"}]
        p.fastly_services = services
        asyncio.run(self.t.sample_account(p))
        self.assertEqual(self.t.totals(7, "fastly")["out"], 900)
        self.assertEqual(len(self.t.totals(7, "fastly")["servers"]), 2)

    def test_fastly_hourly_tail_covers_the_rollup_lag(self):
        day0 = 1795219200  # 2026-11-20 00:00 UTC, the last rolled-up day
        class P(FakeProv):
            async def _req(self, method, path, **kw):
                if "by=day" in path:
                    return {"data": [{"start_time": day0, "bandwidth": 100}]}
                return {"data": [{"start_time": day0 + 86400 * 2 + 3600 * h, "bandwidth": 10} for h in range(3)]
                        + [{"start_time": day0 + 3600, "bandwidth": 999}]}  # hour inside the rolled day: ignored
        asyncio.run(self.t.sample_account(P("fastly", {})))
        # reading again (more hours arrived) must not double count, and old month rows must not add up
        self.t.record("fastly:all", 7, "x", buckets={"2026-11": (5000, 0)})
        asyncio.run(self.t.sample_account(P("fastly", {})))
        self.assertEqual(self.t.totals(7, "fastly")["out"], 100 + 30)


if __name__ == "__main__":
    unittest.main()
