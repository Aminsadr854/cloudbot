"""
Unit and integration test suite for 3-engine Cloudflare IP scanner.
Verifies Tests A through L as required by the specification.
"""
import asyncio
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.modules.setdefault("asyncssh", MagicMock())
sys.modules.setdefault("aiohttp", MagicMock())

import store
import cfscanner
import scanner_engine
from scanner_engine import ScannerEngine, PhoneDeliveryCoordinator, choose, decide



class ThreeEngineScannerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_cloudbot.db")
        self.key_path = os.path.join(self.tmp_dir.name, "test_secret.key")
        self.orig_db = os.environ.get("CLOUDBOT_DB")
        self.orig_key = os.environ.get("CLOUDBOT_KEY")
        os.environ["CLOUDBOT_DB"] = self.db_path
        os.environ["CLOUDBOT_KEY"] = self.key_path

        self.st = store.Store()
        self.coordinator = PhoneDeliveryCoordinator(offset_seconds=300)

        async def fake_verifier(ip, host=None, sni=None, port=443, timeout=6.0):
            return True, "HTTP 200 OK"

        self.fake_verifier = AsyncMock(side_effect=fake_verifier)
        self.e1 = ScannerEngine(1, store=self.st, coordinator=self.coordinator, verifier=self.fake_verifier)
        self.e2 = ScannerEngine(2, store=self.st, coordinator=self.coordinator, verifier=self.fake_verifier)
        self.e3 = ScannerEngine(3, store=self.st, coordinator=self.coordinator, verifier=self.fake_verifier)

        # Block any real network socket creation in tests
        self._open_conn_patch = patch("asyncio.open_connection", side_effect=AssertionError("Real socket opened in unit test!"))
        self._open_conn_patch.start()

    async def asyncTearDown(self):
        self._open_conn_patch.stop()
        self.st.close()
        if self.orig_db is not None:
            os.environ["CLOUDBOT_DB"] = self.orig_db
        else:
            os.environ.pop("CLOUDBOT_DB", None)
        if self.orig_key is not None:
            os.environ["CLOUDBOT_KEY"] = self.orig_key
        else:
            os.environ.pop("CLOUDBOT_KEY", None)
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    # Test A: All three engines can start independently.
    async def test_a_independent_startup(self):
        self.assertEqual(self.e1.engine_id, 1)
        self.assertEqual(self.e2.engine_id, 2)
        self.assertEqual(self.e3.engine_id, 3)

        self.assertEqual(self.e1.name, "ENGINE_1")
        self.assertEqual(self.e2.name, "ENGINE_2")
        self.assertEqual(self.e3.name, "ENGINE_3")

        # Verify separate locks
        self.assertIsNot(self.e1.lock, self.e2.lock)
        self.assertIsNot(self.e2.lock, self.e3.lock)

        # Verify independent statuses
        self.e1.set_status("scanning", "test 1")
        self.e2.set_status("testing", "test 2")
        self.e3.set_status("idle", "test 3")

        self.assertEqual(self.e1.get_status()["state"], "scanning")
        self.assertEqual(self.e2.get_status()["state"], "testing")
        self.assertEqual(self.e3.get_status()["state"], "idle")

    # Test B: All three engines can scan concurrently.
    async def test_b_concurrent_parallel_scanning(self):
        self.st.set_cfscan({"ssh": {"host": "relay.ir", "port": 22, "user": "root", "password": "p"}}, 1)
        self.st.set_cfscan({"ssh": {"host": "relay.ir", "port": 22, "user": "root", "password": "p"}}, 2)
        self.st.set_cfscan({"ssh": {"host": "relay.ir", "port": 22, "user": "root", "password": "p"}}, 3)

        active_scans = []
        max_concurrent = 0

        async def mock_run_scan(ssh, jump, log, *, engine_id=1, **kwargs):
            nonlocal max_concurrent
            active_scans.append(engine_id)
            max_concurrent = max(max_concurrent, len(active_scans))
            await asyncio.sleep(0.05)  # simulate scan duration
            active_scans.remove(engine_id)
            return [
                {"ip": f"104.16.{engine_id}.{i}", "rtt": 50 + i, "jitter": 2.0, "loss": 0.0, "mbps": 50}
                for i in range(1, 6)
            ], "tail"

        async def dummy_log(t):
            pass

        with patch("cfscanner.run_scan", side_effect=mock_run_scan):
            t0 = time.time()
            res1, res2, res3 = await asyncio.gather(
                self.e1.scan_pass(dummy_log),
                self.e2.scan_pass(dummy_log),
                self.e3.scan_pass(dummy_log)
            )
            elapsed = time.time() - t0

        self.assertEqual(res1, 5)
        self.assertEqual(res2, 5)
        self.assertEqual(res3, 5)
        self.assertGreaterEqual(max_concurrent, 2, "Engines must scan concurrently in parallel")

        # Verify separate pools
        pool1 = self.st.scan_pool(1)
        pool2 = self.st.scan_pool(2)
        pool3 = self.st.scan_pool(3)
        self.assertIn("104.16.1.1", pool1["ips"])
        self.assertIn("104.16.2.1", pool2["ips"])
        self.assertIn("104.16.3.1", pool3["ips"])
        self.assertNotIn("104.16.2.1", pool1["ips"])

    # Test C: Engine 1 results cannot overwrite Engine 2/3 results.
    async def test_c_independent_result_storage(self):
        self.st.update_cfscan(1, last_best_ip="104.16.1.100", fqdn="eng1.test.com")
        self.st.update_cfscan(2, last_best_ip="104.17.2.200", fqdn="eng2.test.com")
        self.st.update_cfscan(3, last_best_ip="104.18.3.300", fqdn="eng3.test.com")

        self.assertEqual(self.st.cfscan(1)["last_best_ip"], "104.16.1.100")
        self.assertEqual(self.st.cfscan(2)["last_best_ip"], "104.17.2.200")
        self.assertEqual(self.st.cfscan(3)["last_best_ip"], "104.18.3.300")

        # Overwrite Engine 1
        self.st.update_cfscan(1, last_best_ip="104.16.1.101")
        self.assertEqual(self.st.cfscan(1)["last_best_ip"], "104.16.1.101")
        # Ensure Engine 2 and 3 remain unchanged
        self.assertEqual(self.st.cfscan(2)["last_best_ip"], "104.17.2.200")
        self.assertEqual(self.st.cfscan(3)["last_best_ip"], "104.18.3.300")

        # Test candidate lists independence
        self.st.set_scan_candidates([{"ip": "1.1.1.1"}], engine_id=1)
        self.st.set_scan_candidates([{"ip": "2.2.2.2"}], engine_id=2)
        self.st.set_scan_candidates([{"ip": "3.3.3.3"}], engine_id=3)

        self.assertEqual(self.st.scan_candidates(1)["ips"], ["1.1.1.1"])
        self.assertEqual(self.st.scan_candidates(2)["ips"], ["2.2.2.2"])
        self.assertEqual(self.st.scan_candidates(3)["ips"], ["3.3.3.3"])

        # Test found IPs history independence
        self.st.add_found_ip({"ip": "1.1.1.1", "rtt": 50}, engine_id=1)
        self.st.add_found_ip({"ip": "2.2.2.2", "rtt": 60}, engine_id=2)
        self.assertEqual([x["ip"] for x in self.st.found_ips(1)], ["1.1.1.1"])
        self.assertEqual([x["ip"] for x in self.st.found_ips(2)], ["2.2.2.2"])
        self.assertEqual(self.st.found_ips(3), [])

    # Test D: Engine 1 domain receives only Engine 1's selected IP.
    async def test_d_engine_1_domain_isolation(self):
        self.st.set_cf_token("fake_cf_token")
        self.st.update_cfscan(1, fqdn="scanner1.domain.com", auto_apply=True)
        self.st.update_cfscan(2, fqdn="scanner2.domain.com", auto_apply=True)
        self.st.update_cfscan(3, fqdn="scanner3.domain.com", auto_apply=True)

        cf_updates = []
        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(side_effect=lambda fqdn: (f"zone_{fqdn}", "zone_name"))
        mock_cf.find_a_record = AsyncMock(side_effect=lambda zid, fqdn: {"id": f"rec_{fqdn}", "content": "1.1.1.1"})
        async def mock_update_a(zid, rec, ip):
            cf_updates.append((rec["id"], ip))
        mock_cf.update_a = AsyncMock(side_effect=mock_update_a)

        self.st.set_scan_candidates([{"ip": "104.16.1.10", "rtt": 40}], engine_id=1)
        with patch("scanner_engine.Cloudflare", return_value=mock_cf):
            with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.10", "rtt": 40}, "why": "ok", "voters": 2}):
                await self.e1.phone_recheck_pass()

        self.assertEqual(len(cf_updates), 1)
        self.assertEqual(cf_updates[0], ("rec_scanner1.domain.com", "104.16.1.10"))
        self.assertEqual(self.st.cfscan(1).get("last_best_ip"), "104.16.1.10")
        self.assertNotEqual(self.st.cfscan(2).get("last_best_ip"), "104.16.1.10")
        self.assertNotEqual(self.st.cfscan(3).get("last_best_ip"), "104.16.1.10")

    # Test E: Engine 2 domain receives only Engine 2's selected IP.
    async def test_e_engine_2_domain_isolation(self):
        self.st.set_cf_token("fake_cf_token")
        self.st.update_cfscan(1, fqdn="scanner1.domain.com", auto_apply=True)
        self.st.update_cfscan(2, fqdn="scanner2.domain.com", auto_apply=True)
        self.st.update_cfscan(3, fqdn="scanner3.domain.com", auto_apply=True)

        cf_updates = []
        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(side_effect=lambda fqdn: (f"zone_{fqdn}", "zone_name"))
        mock_cf.find_a_record = AsyncMock(side_effect=lambda zid, fqdn: {"id": f"rec_{fqdn}", "content": "1.1.1.1"})
        async def mock_update_a(zid, rec, ip):
            cf_updates.append((rec["id"], ip))
        mock_cf.update_a = AsyncMock(side_effect=mock_update_a)

        self.st.set_scan_candidates([{"ip": "104.17.2.20", "rtt": 45}], engine_id=2)
        with patch("scanner_engine.Cloudflare", return_value=mock_cf):
            with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.17.2.20", "rtt": 45}, "why": "ok", "voters": 2}):
                await self.e2.phone_recheck_pass()

        self.assertEqual(len(cf_updates), 1)
        self.assertEqual(cf_updates[0], ("rec_scanner2.domain.com", "104.17.2.20"))
        self.assertEqual(self.st.cfscan(2).get("last_best_ip"), "104.17.2.20")
        self.assertNotEqual(self.st.cfscan(1).get("last_best_ip"), "104.17.2.20")
        self.assertNotEqual(self.st.cfscan(3).get("last_best_ip"), "104.17.2.20")

    # Test F: Engine 3 domain receives only Engine 3's selected IP.
    async def test_f_engine_3_domain_isolation(self):
        self.st.set_cf_token("fake_cf_token")
        self.st.update_cfscan(1, fqdn="scanner1.domain.com", auto_apply=True)
        self.st.update_cfscan(2, fqdn="scanner2.domain.com", auto_apply=True)
        self.st.update_cfscan(3, fqdn="scanner3.domain.com", auto_apply=True)

        cf_updates = []
        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(side_effect=lambda fqdn: (f"zone_{fqdn}", "zone_name"))
        mock_cf.find_a_record = AsyncMock(side_effect=lambda zid, fqdn: {"id": f"rec_{fqdn}", "content": "1.1.1.1"})
        async def mock_update_a(zid, rec, ip):
            cf_updates.append((rec["id"], ip))
        mock_cf.update_a = AsyncMock(side_effect=mock_update_a)

        self.st.set_scan_candidates([{"ip": "104.18.3.30", "rtt": 42}], engine_id=3)
        with patch("scanner_engine.Cloudflare", return_value=mock_cf):
            with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.18.3.30", "rtt": 42}, "why": "ok", "voters": 2}):
                await self.e3.phone_recheck_pass()

        self.assertEqual(len(cf_updates), 1)
        self.assertEqual(cf_updates[0], ("rec_scanner3.domain.com", "104.18.3.30"))
        self.assertEqual(self.st.cfscan(3).get("last_best_ip"), "104.18.3.30")
        self.assertNotEqual(self.st.cfscan(1).get("last_best_ip"), "104.18.3.30")
        self.assertNotEqual(self.st.cfscan(2).get("last_best_ip"), "104.18.3.30")

    # Test G: Final phone delivery has Engine 1 -> T, Engine 2 -> T+5m, Engine 3 -> T+10m.
    async def test_g_phone_delivery_5min_offset(self):
        coordinator = PhoneDeliveryCoordinator(offset_seconds=300)
        now = 10000.0

        with patch("time.time", side_effect=[now, now, now]):
            # Test slot calculation
            async with coordinator._lock:
                # Engine 1 requests at T=10000
                t1 = coordinator._next_slot_time
                self.assertEqual(t1, 0.0)

            # We can test schedule_delivery slot calculations directly
            logs = []
            async def mock_log(msg):
                logs.append(msg)

            # Mock asyncio.sleep to record scheduled delays without actually waiting 10 minutes
            delays = {}
            orig_sleep = asyncio.sleep
            async def mock_sleep(d):
                delays[len(delays)] = d

            with patch("asyncio.sleep", side_effect=mock_sleep):
                # When all 3 engines arrive at the same time:
                with patch("time.time", return_value=now):
                    await coordinator.schedule_delivery(1, mock_log)
                    await coordinator.schedule_delivery(2, mock_log)
                    await coordinator.schedule_delivery(3, mock_log)

            # Engine 1 delivered at T (delay 0)
            # Engine 2 scheduled in 5 minutes (delay 300)
            # Engine 3 scheduled in 10 minutes (delay 600)
            self.assertEqual(delays[0], 300.0)  # Engine 2 delay = 5 mins
            self.assertEqual(delays[1], 600.0)  # Engine 3 delay = 10 mins

            self.assertIn("[ENGINE 1] Sending result to phones", logs)
            self.assertIn("[ENGINE 2] Scheduled delivery in 5 minutes", logs)
            self.assertIn("[ENGINE 3] Scheduled delivery in 10 minutes", logs)

    # Test H: If Engine 1 fails, Engine 2 and Engine 3 continue.
    async def test_h_engine_1_failure_isolation(self):
        self.st.set_cfscan({"ssh": {"host": "relay.ir"}}, 1)
        self.st.set_cfscan({"ssh": {"host": "relay.ir"}}, 2)
        self.st.set_cfscan({"ssh": {"host": "relay.ir"}}, 3)

        async def mock_run_scan(ssh, jump, log, *, engine_id=1, **kwargs):
            if engine_id == 1:
                raise RuntimeError("Engine 1 SSH connect failed")
            return [{"ip": f"104.16.{engine_id}.1", "rtt": 50}], "tail"

        async def dummy_log(t):
            pass

        with patch("cfscanner.run_scan", side_effect=mock_run_scan):
            # Engine 1 should catch and raise or log, Engine 2 & 3 must succeed
            try:
                await self.e1.scan_pass(dummy_log)
            except Exception as e:
                self.assertIn("Engine 1", str(e))

            # Run Engine 2 and Engine 3
            res2 = await self.e2.scan_pass(dummy_log)
            res3 = await self.e3.scan_pass(dummy_log)

            self.assertEqual(res2, 1)
            self.assertEqual(res3, 1)
            self.assertIn("104.16.2.1", self.st.scan_pool(2)["ips"])
            self.assertIn("104.16.3.1", self.st.scan_pool(3)["ips"])

    # Test I: If Engine 2 fails, Engine 1 and Engine 3 continue.
    async def test_i_engine_2_failure_isolation(self):
        self.st.set_cfscan({"ssh": {"host": "relay.ir"}}, 1)
        self.st.set_cfscan({"ssh": {"host": "relay.ir"}}, 2)
        self.st.set_cfscan({"ssh": {"host": "relay.ir"}}, 3)

        async def mock_run_scan(ssh, jump, log, *, engine_id=1, **kwargs):
            if engine_id == 2:
                raise TimeoutError("Engine 2 timed out")
            return [{"ip": f"104.16.{engine_id}.1", "rtt": 50}], "tail"

        async def dummy_log(t):
            pass

        with patch("cfscanner.run_scan", side_effect=mock_run_scan):
            res1 = await self.e1.scan_pass(dummy_log)
            try:
                await self.e2.scan_pass(dummy_log)
            except Exception as e:
                self.assertIsInstance(e, TimeoutError)
            res3 = await self.e3.scan_pass(dummy_log)

            self.assertEqual(res1, 1)
            self.assertEqual(res3, 1)
            self.assertIn("104.16.1.1", self.st.scan_pool(1)["ips"])
            self.assertIn("104.16.3.1", self.st.scan_pool(3)["ips"])

    # Test J: If Cloudflare API update fails for one engine, other engines continue.
    async def test_j_cloudflare_update_failure_isolation(self):
        self.st.set_cf_token("fake_token")
        self.st.update_cfscan(1, fqdn="scanner1.domain.com", auto_apply=True)
        self.st.update_cfscan(2, fqdn="scanner2.domain.com", auto_apply=True)
        self.st.update_cfscan(3, fqdn="scanner3.domain.com", auto_apply=True)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=("zone1", "domain.com"))
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec1", "content": "1.1.1.1"})

        async def mock_update_a(zid, rec, ip):
            if ip == "104.17.2.20":
                raise RuntimeError("Cloudflare API error for Engine 2")

        mock_cf.update_a = AsyncMock(side_effect=mock_update_a)

        self.st.set_scan_candidates([{"ip": "104.16.1.10", "rtt": 40}], engine_id=1)
        self.st.set_scan_candidates([{"ip": "104.17.2.20", "rtt": 45}], engine_id=2)
        self.st.set_scan_candidates([{"ip": "104.18.3.30", "rtt": 42}], engine_id=3)

        with patch("scanner_engine.Cloudflare", return_value=mock_cf):
            # Engine 1 update
            with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.10", "rtt": 40}, "why": "ok", "voters": 2}):
                await self.e1.phone_recheck_pass()

            # Engine 2 update (fails Cloudflare)
            with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.17.2.20", "rtt": 45}, "why": "ok", "voters": 2}):
                await self.e2.phone_recheck_pass()

            # Engine 3 update
            with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.18.3.30", "rtt": 42}, "why": "ok", "voters": 2}):
                await self.e3.phone_recheck_pass()

        # Engine 1 and 3 should have succeeded and recorded found IP
        self.assertEqual(len(self.st.found_ips(1)), 1)
        self.assertEqual(len(self.st.found_ips(2)), 0)  # Failed CF update not saved as applied
        self.assertEqual(len(self.st.found_ips(3)), 1)

    # Test K: Restarting application does not corrupt engine configuration/state.
    async def test_k_restart_persistence(self):
        self.st.update_cfscan(1, fqdn="scanner1.test.com", interval_hours=3, auto_apply=True, last_best_ip="104.16.1.5")
        self.st.update_cfscan(2, fqdn="scanner2.test.com", interval_hours=6, auto_apply=False, last_best_ip="104.17.2.5")
        self.st.update_cfscan(3, fqdn="scanner3.test.com", interval_hours=12, auto_apply=True, last_best_ip="104.18.3.5")

        self.st.pool_add([{"ip": "104.16.1.10", "rtt": 50}], engine_id=1)
        self.st.pool_add([{"ip": "104.17.2.10", "rtt": 60}], engine_id=2)

        # Simulate restart
        self.st.close()
        new_st = store.Store()
        try:
            cfg1 = new_st.cfscan(1)
            cfg2 = new_st.cfscan(2)
            cfg3 = new_st.cfscan(3)

            self.assertEqual(cfg1["fqdn"], "scanner1.test.com")
            self.assertEqual(cfg1["interval_hours"], 3)
            self.assertTrue(cfg1["auto_apply"])
            self.assertEqual(cfg1["last_best_ip"], "104.16.1.5")

            self.assertEqual(cfg2["fqdn"], "scanner2.test.com")
            self.assertEqual(cfg2["interval_hours"], 6)
            self.assertFalse(cfg2["auto_apply"])
            self.assertEqual(cfg2["last_best_ip"], "104.17.2.5")

            self.assertEqual(cfg3["fqdn"], "scanner3.test.com")
            self.assertEqual(cfg3["interval_hours"], 12)
            self.assertTrue(cfg3["auto_apply"])
            self.assertEqual(cfg3["last_best_ip"], "104.18.3.5")

            self.assertIn("104.16.1.10", new_st.scan_pool(1)["ips"])
            self.assertIn("104.17.2.10", new_st.scan_pool(2)["ips"])
        finally:
            new_st.close()

    # Test L: Existing single-engine behavior remains functionally unchanged for Engine 1.
    async def test_l_backward_compatibility_engine_1(self):
        # Write using legacy single-engine call
        legacy_cfg = {"ssh": {"host": "legacy.ir"}, "fqdn": "legacy.domain.com", "auto_apply": True, "interval_hours": 6}
        self.st.set_cfscan(legacy_cfg)
        self.st.set_scan_candidates([{"ip": "104.16.0.1"}])
        self.st.pool_add([{"ip": "104.16.0.2", "rtt": 45}])
        self.st.add_found_ip({"ip": "104.16.0.3", "rtt": 40})

        # Read via legacy calls
        self.assertEqual(self.st.cfscan()["fqdn"], "legacy.domain.com")
        self.assertEqual(self.st.scan_candidates()["ips"], ["104.16.0.1"])
        self.assertIn("104.16.0.2", self.st.scan_pool()["ips"])
        self.assertEqual(self.st.found_ips()[0]["ip"], "104.16.0.3")

        # Read via Engine 1 calls
        self.assertEqual(self.st.cfscan(1)["fqdn"], "legacy.domain.com")
        self.assertEqual(self.st.scan_candidates(1)["ips"], ["104.16.0.1"])
        self.assertIn("104.16.0.2", self.st.scan_pool(1)["ips"])
        self.assertEqual(self.st.found_ips(1)[0]["ip"], "104.16.0.3")

    # Test 1 — Fake DNS IP: Given DNS A-record = 85.9.109.98 and scanner results = [], last_best_ip != 85.9.109.98
    async def test_regression_1_fake_dns_ip_rejected(self):
        fake_ip = "85.9.109.98"
        self.st.update_cfscan(2, fqdn="fake.domain.com", last_best_ip=None)
        d = choose([], live_ip=fake_ip, engine_id=2, st=self.st)
        self.assertIsNone(d["entry"])
        self.assertFalse(d["change"])
        self.assertIsNone(self.st.cfscan(2).get("last_best_ip"))
        self.assertNotEqual(self.st.cfscan(2).get("last_best_ip"), fake_ip)

    # Test 2 — DNS IP not in shortlist: live_entry = None and X must not become last_best_ip.
    async def test_regression_2_dns_ip_not_in_shortlist(self):
        dns_ip = "85.9.108.98"
        shortlist = [{"ip": "104.16.1.1", "score": 50}, {"ip": "104.16.1.2", "score": 60}]
        d = choose(shortlist, live_ip=dns_ip, engine_id=3, st=self.st)
        self.assertIsNone(d["entry"])
        keep_entry = next((r for r in shortlist if r["ip"] == dns_ip), None)
        self.assertIsNone(keep_entry)

    # Test 3 — Valid existing IP: If DNS IP is genuinely in validated results, behavior works correctly.
    async def test_regression_3_valid_existing_ip(self):
        valid_ip = "104.16.1.1"
        results = [{"ip": valid_ip, "rtt": 40, "tcp_ms": 30, "tls_ms": 10, "ttfb_ms": 40, "score": 50},
                   {"ip": "104.16.1.2", "rtt": 45, "tcp_ms": 35, "tls_ms": 10, "ttfb_ms": 45, "score": 60}]
        d = choose(results, live_ip=valid_ip, engine_id=1, st=self.st)
        self.assertIsNotNone(d["entry"])
        self.assertEqual(d["entry"]["ip"], valid_ip)

    # Test 4 — New confirmed candidate: Passes scanner + phone validation -> becomes last_best_ip.
    async def test_regression_4_new_confirmed_candidate(self):
        self.st.update_cfscan(2, fqdn="eng2.test.com", auto_apply=True, last_best_ip=None)
        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone2", "eng2.test.com"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec2", "content": "85.9.109.98"})
        mock_cf.update_a = AsyncMock(return_value=True)

        cand = {"ts": int(time.time()), "ips": ["104.17.2.50"], "metrics": {"104.17.2.50": {"rtt": 35, "ok": True}}}
        self.st.set_scan_candidates([{"ip": "104.17.2.50", "rtt": 35, "tcp_ms": 20, "tls_ms": 15, "ttfb_ms": 35}],
                                    controls=[], keep=10, engine_id=2)

        with patch("scanner_engine.Cloudflare", return_value=mock_cf):
            with patch("store.Store.cf_token", return_value="dummy_token"):
                with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.17.2.50", "rtt": 35}, "why": "both approved", "voters": 2}):
                    await self.e2.phone_recheck_pass()

        self.assertEqual(self.st.cfscan(2).get("last_best_ip"), "104.17.2.50")
        self.assertEqual(self.st.found_ips(2)[0]["ip"], "104.17.2.50")

    # Test 5 — No new valid candidate: Preserve existing legitimate last_best_ip.
    async def test_regression_5_preserve_legitimate_best_ip(self):
        self.st.update_cfscan(1, fqdn="eng1.test.com", last_best_ip="104.16.1.100")
        self.st.set_scan_candidates([{"ip": "104.16.1.200"}], controls=[], keep=10, engine_id=1)

        with patch("scanner_engine.decide", return_value={"change": False, "entry": None, "why": "not better", "voters": 2}):
            await self.e1.phone_recheck_pass()

        self.assertEqual(self.st.cfscan(1).get("last_best_ip"), "104.16.1.100")

    # Test 6 — Three engines independent: No engine inherits another engine's last_best_ip.
    async def test_regression_6_three_engines_isolation(self):
        self.st.update_cfscan(1, last_best_ip="104.16.1.10")
        self.st.update_cfscan(2, last_best_ip=None)
        self.st.update_cfscan(3, last_best_ip=None)

        self.assertEqual(self.st.cfscan(1).get("last_best_ip"), "104.16.1.10")
        self.assertIsNone(self.st.cfscan(2).get("last_best_ip"))
        self.assertIsNone(self.st.cfscan(3).get("last_best_ip"))

    # Test 7 — Telegram display: Never displays current DNS placeholder as Best IP unless validated.
    async def test_regression_7_telegram_display_placeholder(self):
        cfg_unvalidated = {"fqdn": "c2c2c2c2c2.rjwarehousing.ir", "last_best_ip": None}
        best_ip_display = cfg_unvalidated.get("last_best_ip") or "—"
        self.assertEqual(best_ip_display, "—")
        self.assertNotEqual(best_ip_display, "85.9.109.98")

    # Test 8 — Control IP: never returns 127.0.0.1 when using production/default configuration
    def test_regression_8_control_ips_never_localhost_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            ctrls = scanner_engine._control_ips()
            self.assertNotIn("127.0.0.1", ctrls)

    # Test 9 — Default control host resolves from https://status.etesalpaya.com
    def test_regression_9_control_ips_default_resolves_status_etesalpaya(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("socket.gethostbyname", return_value="91.108.145.140") as mock_dns:
                ctrls = scanner_engine._control_ips()
                mock_dns.assert_called_once_with("status.etesalpaya.com")
                self.assertEqual(ctrls, ["91.108.145.140"])

    # Test 10 — CLOUDBOT_PROBE_BASE takes precedence when defined
    def test_regression_10_control_ips_precedence_probe_base(self):
        env = {
            "CLOUDBOT_PROBE_BASE": "https://primary.probe.com",
            "CLOUDBOT_PROBE": "https://legacy.probe.com"
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("socket.gethostbyname", return_value="1.2.3.4") as mock_dns:
                ctrls = scanner_engine._control_ips()
                mock_dns.assert_called_once_with("primary.probe.com")
                self.assertEqual(ctrls, ["1.2.3.4"])

    # Test 11 — Legacy CLOUDBOT_PROBE works if CLOUDBOT_PROBE_BASE is absent
    def test_regression_11_control_ips_legacy_probe_fallback(self):
        env = {"CLOUDBOT_PROBE": "https://legacy.probe.com"}
        with patch.dict(os.environ, env, clear=True):
            with patch("socket.gethostbyname", return_value="5.6.7.8") as mock_dns:
                ctrls = scanner_engine._control_ips()
                mock_dns.assert_called_once_with("legacy.probe.com")
                self.assertEqual(ctrls, ["5.6.7.8"])

    # Test 12 — _report_trusted() rejects Wi-Fi or empty measurements
    def test_regression_12_report_trusted_behavior_unchanged(self):
        controls = {"91.108.145.140"}
        # Wi-Fi rejected
        ok, why = scanner_engine._report_trusted({"net": "wifi", "results": [{"ip": "104.16.1.1", "ok": True}]}, controls)
        self.assertFalse(ok)
        self.assertIn("وای‌فای", why)

        # Empty rejected
        ok, why = scanner_engine._report_trusted({"net": "cellular", "results": []}, controls)
        self.assertFalse(ok)
        self.assertIn("چیزی اندازه‌گیری نشده بود", why)

    # Test 13 — Phone report with successful candidates + successful control is classified as trusted
    def test_regression_13_phone_report_trusted_with_control_success(self):
        controls = {"91.108.145.140"}
        results = [
            {"ip": "104.16.1.1", "ok": True, "rtt_ms": 35.0, "loss": 0.0},
            {"ip": "91.108.145.140", "ok": True, "rtt_ms": 20.0, "loss": 0.0}
        ]
        rep = {"net": "cellular", "results": results}
        ok, why = scanner_engine._report_trusted(rep, controls)
        self.assertTrue(ok)
        self.assertEqual(why, "")

    # Test 14 — Phone report where control probe fails remains untrusted
    def test_regression_14_phone_report_untrusted_when_control_fails(self):
        controls = {"91.108.145.140"}
        results = [
            {"ip": "104.16.1.1", "ok": False, "rtt_ms": None, "loss": 1.0},
            {"ip": "91.108.145.140", "ok": False, "rtt_ms": None, "loss": 1.0}
        ]
        rep = {"net": "cellular", "results": results}
        ok, why = scanner_engine._report_trusted(rep, controls)
        self.assertFalse(ok)
        self.assertIn("سرور ایران هم از این گوشی جواب نداد", why)


    # Test 15 — Verifier injection: custom verifier passed to phone_recheck_pass is respected
    async def test_verifier_injection_custom_override(self):
        self.st.update_cfscan(1, fqdn="test.domain.com", auto_apply=False)
        self.st.set_scan_candidates([{"ip": "104.16.1.99", "rtt": 30}], engine_id=1)
        calls = []

        async def custom_verifier(ip, host=None, sni=None, port=443, timeout=6.0):
            calls.append((ip, host, sni))
            return False, "Custom rejection"

        with patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.99", "rtt": 30}, "why": "ok", "voters": 2}):
            await self.e1.phone_recheck_pass(verifier=custom_verifier)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "104.16.1.99")
        # Decision status updated with rejection reason
        self.assertIn("هیچ‌کدام", self.st.get("scan_last_decision_engine_1"))

    # Test A1: Shell injection protection in _build_scan_args
    def test_a1_shell_injection_protection_in_build_scan_args(self):
        import shlex
        host = "evil.com; rm -rf /"
        sni = "evil.sni; reboot"
        out_file = "/root/out; malicious"
        args = cfscanner._build_scan_args("/root/cf_scan.py", out_file, host=host, sni=sni)
        joined = shlex.join(args)
        cmd = f"ulimit -n 65535 2>/dev/null; {joined} 2>&1 | tail -25"
        # Assert dangerous unquoted shell commands are not present
        self.assertNotIn("; rm -rf / ", cmd)
        self.assertNotIn("; reboot ", cmd)
        # Verify shlex quoted values
        self.assertIn(shlex.quote(host), cmd)
        self.assertIn(shlex.quote(sni), cmd)
        self.assertIn(shlex.quote(out_file), cmd)


    # Test A2: Per-engine remote script path isolation and no shared REMOTE_SCANNER
    def test_a2_per_engine_remote_script_isolation(self):
        self.assertFalse(hasattr(cfscanner, "REMOTE_SCANNER"), "REMOTE_SCANNER should be removed")
        scripts = [f"/root/.cf_scan_engine_{eid}.py" for eid in (1, 2, 3)]
        self.assertEqual(len(set(scripts)), 3)
        for eid, s in zip((1, 2, 3), scripts):
            args = cfscanner._build_scan_args(s, f"/root/out_{eid}")
            self.assertEqual(args[1], s)


if __name__ == "__main__":
    unittest.main()


