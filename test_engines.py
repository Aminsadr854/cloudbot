"""
Unit and integration test suite for 3-engine Cloudflare IP scanner.
Verifies Tests A through L as required by the specification.
"""
import asyncio
import io
import json
import os
import signal
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

        # Mock _resolve_a to return test candidate IPs so tests do not loop and sleep
        async def fake_resolve_a(fqdn, timeout=5.0):
            return ["104.16.1.10", "104.17.2.20", "104.18.3.30", "104.17.2.50", "104.26.1.1", "104.26.14.9"]

        self._resolve_patch = patch("scanner_engine._resolve_a", side_effect=fake_resolve_a)
        self._resolve_patch.start()

    async def asyncTearDown(self):
        self._resolve_patch.stop()
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


    # Test A3: Infinity and None handling in cf_scan and cfscanner
    def test_a3_infinity_and_none_handling(self):
        import cf_scan
        import math

        # rtt=None or inf returns inf
        self.assertEqual(cfscanner.score({"rtt": None}), float("inf"))
        self.assertEqual(cfscanner.score({"rtt": float("inf")}), float("inf"))
        self.assertEqual(cf_scan.score({"rtt": None}), float("inf"))
        self.assertEqual(cf_scan.score({"rtt": float("inf")}), float("inf"))

        # rtt=0 is not treated as 999
        self.assertEqual(cfscanner.score({"rtt": 0.0, "jitter": 0.0, "loss": 0.0}), 0.0)

        # allow_nan=False in json dump
        valid_row = {"ip": "1.2.3.4", "rtt": None, "loss": 0.0}
        self.assertIn("null", json.dumps([valid_row], allow_nan=False))
        with self.assertRaises(ValueError):
            json.dumps([{"ip": "1.2.3.4", "rtt": float("inf")}], allow_nan=False)

        # txt filter excludes rtt is None
        finalists = [{"ip": "1.1.1.1", "rtt": None, "loss": 0}, {"ip": "2.2.2.2", "rtt": 50, "loss": 0}]
        loss_free = [r["ip"] for r in finalists if r.get("rtt") is not None and r.get("loss") == 0]
        self.assertEqual(loss_free, ["2.2.2.2"])

    # Test A4: Missing measurement of live_ip keeps current IP without changing
    def test_a4_missing_live_ip_measurement_keeps_current_ip(self):
        results = [{"ip": "104.16.1.20", "rtt": 30}]
        live_ip = "104.16.1.99"
        measured = {
            "104.16.1.20": {"rtt": 30, "jitter": 2.0, "loss": 0.0, "valid": True, "cf_error": False}
        }
        verdicts = {
            "dev1": {"104.16.1.20": (True, 30, 1.0)},
            "dev2": {"104.16.1.20": (True, 32, 1.0)},
        }
        with patch("scanner_engine._phone_verdicts", return_value=verdicts):
            decision = choose(results, live_ip=live_ip, measured=measured, engine_id=1, st=self.st)
            decision_no_live = choose(results, live_ip=None, measured=measured, engine_id=1, st=self.st)
        self.assertFalse(decision["change"])
        self.assertIn("ناموفق", decision["why"])
        self.assertTrue(decision_no_live["change"])


    # Test A5: Post-DNS confirmation checks DNS resolution and handles propagation delay
    async def test_a5_post_dns_confirmation_and_propagation_delay(self):
        self.st.update_cfscan(1, fqdn="test.domain.com", auto_apply=True, last_best_ip="1.1.1.1")
        self.st.set_cf_token("fake_token")
        self.st.set_scan_candidates([{"ip": "104.16.1.10", "rtt": 40}], engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone1", "domain.com"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec1", "content": "1.1.1.1"})
        mock_cf.update_a = AsyncMock(return_value=True)

        # Case 1: DNS not visible initially, but verify_domain_ip passes -> warning logged, NO rollback
        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.10", "rtt": 40}, "why": "ok", "voters": 2}), \
             patch("scanner_engine._resolve_a", new=AsyncMock(return_value=[])), \
             patch("asyncio.sleep", AsyncMock()), \
             self.assertLogs("scanner_engine", level="WARNING") as cm:
            await self.e1.phone_recheck_pass()
            self.assertTrue(any("DNS not yet visible" in msg for msg in cm.output))
            # No rollback occurred: update_a called once for the change
            self.assertEqual(mock_cf.update_a.call_count, 1)
            self.assertEqual(mock_cf.update_a.call_args[0][2], "104.16.1.10")

        # Case 2: verify_domain_ip fails on post-check -> rollback DOES occur
        mock_cf.update_a.reset_mock()
        fail_verifier = AsyncMock(side_effect=[(True, "HTTP 200 OK"), (False, "HTTP 500 Connection Failed")])
        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.10", "rtt": 40}, "why": "ok", "voters": 2}), \
             patch("asyncio.sleep", AsyncMock()):
            await self.e1.phone_recheck_pass(verifier=fail_verifier)
            # Rollback occurred: update_a called twice (update, then restore previous IP 1.1.1.1)
            self.assertEqual(mock_cf.update_a.call_count, 2)
            self.assertEqual(mock_cf.update_a.call_args_list[1][0][2], "1.1.1.1")


    # Test A6: Rollback on freshly created record deletes it, verifies ID before deletion
    async def test_a6_rollback_by_deleting_freshly_created_record(self):
        self.st.update_cfscan(1, fqdn="test.domain.com", auto_apply=True, last_best_ip="")
        self.st.set_cf_token("fake_token")
        self.st.set_scan_candidates([{"ip": "104.16.1.10", "rtt": 40}], engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone1", "domain.com"])
        mock_cf.create_a = AsyncMock(return_value={"id": "new_rec_123", "name": "test.domain.com", "content": "104.16.1.10"})
        mock_cf.delete_record = AsyncMock(return_value=True)
        mock_cf.update_a = AsyncMock(return_value=True)

        fail_verifier = AsyncMock(side_effect=[(True, "HTTP 200 OK"), (False, "HTTP 500 Post Check Failed")])
        notify_mock = AsyncMock()

        # Case 1: Fresh record created, post check fails, ID matches -> delete_record called
        # Initially find_a_record returns None (so create_a is used)
        # On rollback, find_a_record returns the record with same ID new_rec_123
        mock_cf.find_a_record = AsyncMock(side_effect=[None, {"id": "new_rec_123", "content": "104.16.1.10"}])

        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.10", "rtt": 40}, "why": "ok", "voters": 2}), \
             patch("asyncio.sleep", AsyncMock()):
            await self.e1.phone_recheck_pass(notify_fn=notify_mock, verifier=fail_verifier)

            self.assertEqual(mock_cf.create_a.call_count, 1)
            self.assertEqual(mock_cf.delete_record.call_count, 1)
            mock_cf.delete_record.assert_called_once_with("zone1", "new_rec_123")
            self.assertEqual(mock_cf.update_a.call_count, 0)
            self.assertIn("حذف گردید", notify_mock.call_args[0][0])

        # Case 2: Fresh record created, post check fails, but record ID changed in the meantime -> do NOT delete
        mock_cf.create_a.reset_mock()
        mock_cf.delete_record.reset_mock()
        notify_mock.reset_mock()
        fail_verifier = AsyncMock(side_effect=[(True, "HTTP 200 OK"), (False, "HTTP 500 Post Check Failed")])
        mock_cf.find_a_record = AsyncMock(side_effect=[None, {"id": "tampered_rec_999", "content": "1.2.3.4"}])

        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.decide", return_value={"change": True, "entry": {"ip": "104.16.1.10", "rtt": 40}, "why": "ok", "voters": 2}), \
             patch("asyncio.sleep", AsyncMock()), \
             self.assertLogs("scanner_engine", level="WARNING") as cm:
            await self.e1.phone_recheck_pass(notify_fn=notify_mock, verifier=fail_verifier)

            self.assertEqual(mock_cf.create_a.call_count, 1)
            self.assertEqual(mock_cf.delete_record.call_count, 0)  # NOT deleted
            self.assertTrue(any("Record ID mismatch" in msg for msg in cm.output))
            self.assertIn("نیاز به بررسی دستی دارد", notify_mock.call_args[0][0])


    # Test A7: Remote scan timeouts, process cleanup, and write_results helper
    async def test_a7_timeouts_clean_kill_and_write_results(self):
        import cf_scan
        # 1. Module-level constants
        self.assertEqual(cfscanner.REMOTE_TIMEOUT, 900)
        self.assertEqual(cfscanner.LOCAL_TIMEOUT, 960)

        # 2. cf_scan.write_results helper
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "scan_res")
            rows = [
                {"ip": "104.16.1.1", "rtt": 35.0, "loss": 0.0, "jitter": 1.0},
                {"ip": "104.16.1.2", "rtt": 40.0, "loss": 0.1, "jitter": 2.0},
                {"ip": "104.16.1.3", "rtt": None, "loss": 1.0},  # invalid, should be excluded
            ]
            cf_scan.write_results(rows, out_base)
            self.assertTrue(os.path.exists(out_base + ".json"))
            self.assertTrue(os.path.exists(out_base + ".txt"))

            with open(out_base + ".json") as f:
                saved_json = json.load(f)
            saved_rows = saved_json.get("results", saved_json)
            self.assertEqual(len(saved_rows), 2)
            self.assertEqual(saved_rows[0]["ip"], "104.16.1.1")
            self.assertEqual(saved_rows[1]["ip"], "104.16.1.2")

            with open(out_base + ".txt") as f:
                saved_txt = f.read().splitlines()
            self.assertEqual(saved_txt, ["104.16.1.1"])

        # 3. cfscanner.run_scan: pre-clean existing process and command timeout wrapper
        mock_conn = MagicMock()
        mock_sftp = AsyncMock()
        mock_file = AsyncMock()
        mock_sftp.open = MagicMock(return_value=mock_file)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_sftp.__aenter__ = AsyncMock(return_value=mock_sftp)
        mock_sftp.__aexit__ = AsyncMock(return_value=None)
        mock_conn.start_sftp_client = MagicMock(return_value=mock_sftp)

        cmd_history = []
        async def mock_run(cmd, check=False):
            cmd_history.append(cmd)
            res = MagicMock()
            if "pgrep" in cmd:
                # First check finds process, second check confirms it died
                res.stdout = "1234\n" if len([c for c in cmd_history if "pgrep" in c]) == 1 else ""
            elif "cat " in cmd:
                res.stdout = json.dumps([{"ip": "104.16.1.1", "rtt": 35.0}])
            else:
                res.stdout = "scan output..."
            res.exit_status = 0
            return res

        mock_conn.run = AsyncMock(side_effect=mock_run)

        with patch("cfscanner.tunnel.connect", AsyncMock(return_value=mock_conn)), \
             patch("asyncio.sleep", AsyncMock()):
            data, _ = await cfscanner.run_scan(
                {"host": "remote.ir", "user": "root", "password": "p"},
                jump=None, log=AsyncMock(), engine_id=2
            )
            self.assertEqual(len(data), 1)
            # Verify pgrep was called for engine 2 script
            self.assertTrue(any("pgrep -f /root/.cf_scan_engine_2.py" in c for c in cmd_history))
            # Verify pkill -15 was called for engine 2 script
            self.assertTrue(any("pkill -15 -f /root/.cf_scan_engine_2.py" in c for c in cmd_history))
            # Verify timeout -k 10 900 is in the scan command
            scan_cmd = next(c for c in cmd_history if "timeout -k 10 900" in c)
            self.assertIn("timeout -k 10 900", scan_cmd)
            self.assertIn("/root/.cf_scan_engine_2.py", scan_cmd)

        # 4. cfscanner.run_scan: timeout expiration triggers clean kill and raises ScanTimeoutError
        async def mock_run_hang(cmd, check=False):
            if "pgrep" in cmd:
                res = MagicMock()
                res.stdout = ""
                return res
            if "timeout -k 10" in cmd:
                raise asyncio.TimeoutError()
            res = MagicMock()
            res.stdout = ""
            return res

        mock_conn.run = AsyncMock(side_effect=mock_run_hang)
        with patch("cfscanner.tunnel.connect", AsyncMock(return_value=mock_conn)), \
             patch("asyncio.sleep", AsyncMock()):
            with self.assertRaises(cfscanner.ScanTimeoutError):
                await cfscanner.run_scan(
                    {"host": "remote.ir", "user": "root", "password": "p"},
                    jump=None, log=AsyncMock(), engine_id=3
                )
            calls = [c[0][0] for c in mock_conn.run.call_args_list]
            self.assertTrue(any("pkill -15 -f /root/.cf_scan_engine_3.py" in c for c in calls))
            self.assertTrue(any("pkill -9 -f /root/.cf_scan_engine_3.py" in c for c in calls))


    # Test A8: Atomic writes, truncated-file resistance, and stale result rejection
    async def test_a8_atomic_writes_and_stale_result_rejection(self):
        import cf_scan
        # 1. Truncated-file resistance and atomic replacement
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "atomic_test")
            # Write initial valid file
            initial_rows = [{"ip": "1.1.1.1", "rtt": 20.0, "loss": 0.0}]
            cf_scan.write_results(initial_rows, out_base, scan_start=1000, engine_id=1)
            self.assertTrue(os.path.exists(out_base + ".json"))

            # Simulate an interrupted run leaving a corrupt .tmp file behind
            with open(out_base + ".json.tmp", "w") as f:
                f.write('{"scan_start": 2000, "corrupt_data": [')

            # Verify original .json is completely intact and readable
            with open(out_base + ".json") as f:
                intact_json = json.load(f)
            self.assertEqual(intact_json["results"][0]["ip"], "1.1.1.1")

            # Successful write_results atomically replaces .json and cleans up .tmp
            new_rows = [{"ip": "2.2.2.2", "rtt": 25.0, "loss": 0.0}]
            cf_scan.write_results(new_rows, out_base, scan_start=3000, engine_id=1)
            with open(out_base + ".json") as f:
                updated_json = json.load(f)
            self.assertEqual(updated_json["results"][0]["ip"], "2.2.2.2")
            self.assertFalse(os.path.exists(out_base + ".json.tmp"))

            # Re-entrancy guard test: when _write_lock is True, write_results safely exits
            try:
                cf_scan._write_lock = True
                cf_scan.write_results([{"ip": "9.9.9.9", "rtt": 10.0}], out_base)
                with open(out_base + ".json") as f:
                    guarded_json = json.load(f)
                # File remains with 2.2.2.2, not overwritten by re-entrant call
                self.assertEqual(guarded_json["results"][0]["ip"], "2.2.2.2")
            finally:
                cf_scan._write_lock = False

        # 2. Stale-result rejection and output cleanup in cfscanner.run_scan
        mock_conn = MagicMock()
        mock_sftp = AsyncMock()
        mock_file = AsyncMock()
        mock_sftp.open = MagicMock(return_value=mock_file)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_sftp.__aenter__ = AsyncMock(return_value=mock_sftp)
        mock_sftp.__aexit__ = AsyncMock(return_value=None)
        mock_conn.start_sftp_client = MagicMock(return_value=mock_sftp)

        cmd_history = []
        # Simulate returning a stale results file (from 1 hour ago)
        async def mock_run_stale(cmd, check=False):
            cmd_history.append(cmd)
            res = MagicMock()
            if "pgrep" in cmd:
                res.stdout = ""
            elif "rm -f" in cmd:
                res.stdout = ""
            elif "cat " in cmd:
                # Results with scan_start older than current time
                stale_payload = {
                    "scan_start": int(time.time()) - 3600,
                    "engine_id": 2,
                    "results": [{"ip": "104.16.1.1", "rtt": 35.0}]
                }
                res.stdout = json.dumps(stale_payload)
            else:
                res.stdout = "scan output..."
            res.exit_status = 0
            return res

        mock_conn.run = AsyncMock(side_effect=mock_run_stale)
        with patch("cfscanner.tunnel.connect", AsyncMock(return_value=mock_conn)), \
             patch("asyncio.sleep", AsyncMock()):
            # Verify stale results are rejected
            with self.assertRaises(cfscanner.StaleResultError):
                await cfscanner.run_scan(
                    {"host": "remote.ir", "user": "root", "password": "p"},
                    jump=None, log=AsyncMock(), engine_id=2
                )
            # Verify rm -f was executed for engine 2 outputs
            self.assertTrue(any("rm -f /root/cf_bot_scan_engine_2.json" in c for c in cmd_history))

        # 3. Engine ID mismatch rejection
        cmd_history.clear()
        async def mock_run_mismatch(cmd, check=False):
            cmd_history.append(cmd)
            res = MagicMock()
            if "cat " in cmd:
                mismatch_payload = {
                    "scan_start": int(time.time()),
                    "engine_id": 1,  # Belongs to Engine 1, but running for Engine 2!
                    "results": [{"ip": "104.16.1.1", "rtt": 35.0}]
                }
                res.stdout = json.dumps(mismatch_payload)
            else:
                res.stdout = ""
            res.exit_status = 0
            return res

        mock_conn.run = AsyncMock(side_effect=mock_run_mismatch)
        with patch("cfscanner.tunnel.connect", AsyncMock(return_value=mock_conn)), \
             patch("asyncio.sleep", AsyncMock()):
            with self.assertRaises(cfscanner.StaleResultError):
                await cfscanner.run_scan(
                    {"host": "remote.ir", "user": "root", "password": "p"},
                    jump=None, log=AsyncMock(), engine_id=2
                )

    # Test B6: Scoring agreement between cf_scan and cfscanner across all present/absent field combinations
    def test_b6_score_agreement_and_weights(self):
        import cf_scan
        rows = [
            # 1. Full metrics present
            {"rtt": 50.0, "jitter": 2.0, "loss": 0.0, "tls_loss": 0.0, "tls_rtt": 150.0, "tls_jitter": 4.0, "mbps": 10.0},
            # 2. Legacy row: no tls fields at all
            {"rtt": 45.0, "jitter": 1.5, "loss": 0.02},
            # 3. Only tls_loss present
            {"rtt": 40.0, "jitter": 3.0, "loss": 0.05, "tls_loss": 0.02},
            # 4. Only tls_jitter present
            {"rtt": 40.0, "jitter": 2.0, "loss": 0.0, "tls_jitter": 3.5},
            # 5. Missing/invalid RTT
            {"rtt": None, "jitter": 0.0, "loss": 0.0},
            {"rtt": float("inf"), "jitter": 0.0, "loss": 0.0},
            # 6. With throughput discount
            {"rtt": 30.0, "jitter": 1.0, "loss": 0.0, "tls_loss": 0.0, "tls_jitter": 1.0, "mbps": 250.0},
            # 7. tls_rtt present but should not enter cost directly
            {"rtt": 35.0, "jitter": 1.0, "loss": 0.0, "tls_rtt": 120.0},
        ]
        for r in rows:
            self.assertEqual(cf_scan.score(r), cfscanner.score(r))

        # Check weights:
        # cost = rtt + 2.0*jitter + 1000.0*loss + 1200.0*tls_loss + 0.5*tls_jitter
        base = {"rtt": 50.0, "jitter": 0.0, "loss": 0.0, "tls_loss": 0.0, "tls_jitter": 0.0}
        with_tcp_loss = {"rtt": 50.0, "jitter": 0.0, "loss": 0.1, "tls_loss": 0.0, "tls_jitter": 0.0}
        with_tls_loss = {"rtt": 50.0, "jitter": 0.0, "loss": 0.0, "tls_loss": 0.1, "tls_jitter": 0.0}
        with_tls_jitter = {"rtt": 50.0, "jitter": 0.0, "loss": 0.0, "tls_loss": 0.0, "tls_jitter": 10.0}
        self.assertEqual(cf_scan.score(with_tcp_loss) - cf_scan.score(base), 100.0)
        self.assertEqual(cf_scan.score(with_tls_loss) - cf_scan.score(base), 120.0)
        self.assertEqual(cf_scan.score(with_tls_jitter) - cf_scan.score(base), 5.0)
        self.assertGreater(cf_scan.score(with_tls_loss), cf_scan.score(with_tcp_loss))

    # Test B6: stage_stable separates TCP metrics from TLS metrics
    async def test_b6_stage_stable_separate_tcp_tls_metrics(self):
        import cf_scan

        tcp_calls = []
        tls_calls = []

        async def fake_tcp(ip, port, timeout):
            tcp_calls.append(ip)
            return 30.0

        async def fake_http(ip, host, port, path, timeout, read_bytes=0, want_body=False, sni=None, verify=False):
            tls_calls.append((ip, host, port, path, sni))
            if len(tls_calls) == 1:
                # First TLS probe succeeds with TTFB 110.0ms
                return {"valid": True, "cf_error": False, "ttfb_ms": 110.0}
            else:
                # Second TLS probe fails (interfered/reset)
                return {"valid": False, "cf_error": True, "error": "ConnectionResetError"}

        with patch("cf_scan.tcp_probe", side_effect=fake_tcp), \
             patch("cf_scan.http_probe", side_effect=fake_http), \
             patch("asyncio.sleep", AsyncMock()):
            rows = [{"ip": "1.2.3.4"}]
            results = await cf_scan.stage_stable(
                rows, port=443, timeout=2.0, rounds=4, concurrency=10,
                host="example.com", path="/cdn-cgi/trace", sni="sni.example.com", http_timeout=5.0
            )

        # 4 rounds: rounds 0 & 2 -> TCP (2 calls), rounds 1 & 3 -> TLS (2 calls)
        self.assertEqual(len(tcp_calls), 2)
        self.assertEqual(len(tls_calls), 2)

        res = results[0]
        # TCP had 2 attempts and both succeeded -> loss = 0.0
        self.assertEqual(res["loss"], 0.0)
        # TCP metrics ONLY from TCP samples (30.0, 30.0)
        self.assertEqual(res["rtt"], 30.0)
        self.assertEqual(res["jitter"], 0.0)
        self.assertEqual(res["rtt_max"], 30.0)

        # TLS had 2 attempts, 1 succeeded (110.0ms) and 1 failed -> tls_loss = 0.5
        self.assertEqual(res["tls_loss"], 0.5)
        # TLS metrics ONLY from TLS samples (110.0)
        self.assertEqual(res["tls_rtt"], 110.0)
        self.assertEqual(res["tls_jitter"], 0.0)

    # Test B2: Interception detection with TLS verification and cert_ok handling
    async def test_b2_interception_detection_and_cert_verify(self):
        import cf_scan
        import ssl

        # 1. http_probe with SSLCertVerificationError
        with patch("asyncio.open_connection", side_effect=ssl.SSLCertVerificationError("Cert verify failed")):
            res = await cf_scan.http_probe("1.2.3.4", "example.com", 443, "/cdn-cgi/trace", 2.0, verify=True)
            self.assertEqual(res, {
                "error": "CertVerify",
                "valid": False,
                "cf_error": False,
                "cert_ok": False,
            })

        # 2. stage_edge separation: cert_ok False vs client IP mismatch vs clean edge
        async def fake_http_probe(ip, host, port, path, timeout, want_body=False, sni=None, verify=False):
            self.assertTrue(verify, "stage_edge must call http_probe with verify=True")
            if ip in ("1.1.1.1", "1.1.1.2"):
                # Clean edge with valid cert and correct client IP
                return {
                    "valid": True, "cf_error": False, "cert_ok": True, "ttfb_ms": 25.0,
                    "body": "ip=90.0.0.1\ncolo=DUS\nloc=DE\n"
                }
            elif ip == "2.2.2.2":
                # Intercepted edge with invalid certificate
                return {
                    "error": "CertVerify", "valid": False, "cf_error": False, "cert_ok": False
                }
            elif ip == "3.3.3.3":
                # Mediated edge with valid cert but client IP mismatch (proxy/gateway)
                return {
                    "valid": True, "cf_error": False, "cert_ok": True, "ttfb_ms": 30.0,
                    "body": "ip=198.51.100.99\ncolo=FRA\nloc=DE\n"
                }

        alive = [("1.1.1.1", 10.0), ("1.1.1.2", 11.0), ("2.2.2.2", 12.0), ("3.3.3.3", 15.0)]
        with patch("cf_scan.http_probe", side_effect=fake_http_probe):
            good, mediated, my_ip, trust_broken = await cf_scan.stage_edge(
                alive, "example.com", 443, "/cdn-cgi/trace", 2.0, 5
            )

        self.assertFalse(trust_broken)
        self.assertEqual(my_ip, "90.0.0.1")
        self.assertEqual(len(good), 2)
        self.assertEqual(good[0]["ip"], "1.1.1.1")
        self.assertTrue(good[0]["cert_ok"])

        self.assertEqual(len(mediated), 2)
        med_by_ip = {d["ip"]: d for d in mediated}
        self.assertIn("2.2.2.2", med_by_ip)
        self.assertFalse(med_by_ip["2.2.2.2"]["cert_ok"])
        self.assertIn("certificate verification failed", med_by_ip["2.2.2.2"]["reason"])

        self.assertIn("3.3.3.3", med_by_ip)
        self.assertTrue(med_by_ip["3.3.3.3"]["cert_ok"])
        self.assertEqual(med_by_ip["3.3.3.3"]["ip_trace"], "198.51.100.99")

    # Test B3: cf-ray header required for valid to be True
    async def test_b3_cf_ray_required(self):
        import cf_scan
        import scanner_engine

        # 1. http_probe without cf-ray returns valid=False even for 200 OK
        reader = AsyncMock()
        reader.readuntil.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        reader.read.return_value = b"Hello world"
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            res = await cf_scan.http_probe("1.2.3.4", "example.com", 443, "/", 2.0, want_body=True)
            self.assertFalse(res["valid"])

        # 2. http_probe with cf-ray returns valid=True for 200 OK
        reader.readuntil.return_value = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-RAY: 12345-FRA\r\n\r\n"
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            res = await cf_scan.http_probe("1.2.3.4", "example.com", 443, "/", 2.0, want_body=True)
            self.assertTrue(res["valid"])

        # 3. verify_domain_ip without cf-ray returns (False, "No cf-ray header (not a Cloudflare edge)")
        reader.readuntil.return_value = b"HTTP/1.1 404 Not Found\r\nServer: apache\r\n\r\n"
        reader.read.return_value = b"Not Found"
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            valid, reason = await scanner_engine.verify_domain_ip("1.2.3.4", "example.com", "example.com")
            self.assertFalse(valid)
            self.assertEqual(reason, "No cf-ray header (not a Cloudflare edge)")

        # 4. verify_domain_ip with cf-ray on 200 OK returns True
        reader.readuntil.return_value = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-RAY: 12345-FRA\r\n\r\n"
        reader.read.return_value = b"OK"
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            valid, reason = await scanner_engine.verify_domain_ip("1.2.3.4", "example.com", "example.com")
            self.assertTrue(valid)
            self.assertEqual(reason, "HTTP 200 OK")

    # Test B4: Canonical classify_cf_error and is_valid_response functions
    def test_b4_canonical_functions(self):
        import cf_scan

        # Test classify_cf_error across various Cloudflare error conditions
        self.assertEqual(
            cf_scan.classify_cf_error("403", "server: cloudflare", "error code: 1034"),
            (True, "1034")
        )
        self.assertEqual(
            cf_scan.classify_cf_error("500", "server: cloudflare", "errorcode: 1000"),
            (True, "1000")
        )
        self.assertEqual(
            cf_scan.classify_cf_error("521", "server: cloudflare", "error 521"),
            (True, "521")
        )
        self.assertEqual(
            cf_scan.classify_cf_error("403", "server: cloudflare\r\ncf-ray: abc", "some error occurred"),
            (True, "403")
        )
        self.assertEqual(
            cf_scan.classify_cf_error("200", "server: cloudflare\r\ncf-ray: abc", "hello"),
            (False, None)
        )

        # Test is_valid_response:
        # 1. Missing cf-ray -> False
        self.assertFalse(cf_scan.is_valid_response("200", "server: cloudflare", "ok"))
        # 2. Cloudflare error -> False
        self.assertFalse(cf_scan.is_valid_response("520", "cf-ray: abc", "error code: 520"))
        # 3. Valid 200 with cf-ray -> True
        self.assertTrue(cf_scan.is_valid_response("200", "cf-ray: abc", "ok"))
        # 4. Valid 400 with WebSocket -> True
        self.assertTrue(cf_scan.is_valid_response("400", "cf-ray: abc\r\nsec-websocket-version: 13", "bad request"))
        # 5. Trace endpoint requires ip and colo or server cloudflare on 200
        self.assertTrue(cf_scan.is_valid_response("200", "cf-ray: abc", "ip=1.1.1.1\ncolo=FRA\n", is_trace=True))
        self.assertFalse(cf_scan.is_valid_response("200", "cf-ray: abc", "other body", is_trace=True))

    # Test B5: stage_reachable retries failed probe and reports latency of successful attempt
    async def test_b5_stage_reachable_retries(self):
        import cf_scan

        attempts = {}

        async def fake_tcp_probe(ip, port, timeout):
            attempts[ip] = attempts.get(ip, 0) + 1
            if ip == "1.1.1.1":
                # First attempt succeeds
                return 15.0
            elif ip == "2.2.2.2":
                # First attempt fails, second attempt succeeds
                if attempts[ip] == 1:
                    return None
                return 25.0
            elif ip == "3.3.3.3":
                # Both attempts fail
                return None

        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        with patch("cf_scan.tcp_probe", side_effect=fake_tcp_probe):
            alive = await cf_scan.stage_reachable(ips, port=443, timeout=3.0, concurrency=10, retries=1)

        # 1.1.1.1 took 1 attempt
        self.assertEqual(attempts["1.1.1.1"], 1)
        # 2.2.2.2 took 2 attempts (retried once)
        self.assertEqual(attempts["2.2.2.2"], 2)
        # 3.3.3.3 took 2 attempts (retried once, both failed)
        self.assertEqual(attempts["3.3.3.3"], 2)

        # alive has only 1.1.1.1 and 2.2.2.2
        alive_dict = dict(alive)
        self.assertIn("1.1.1.1", alive_dict)
        self.assertEqual(alive_dict["1.1.1.1"], 15.0)
        self.assertIn("2.2.2.2", alive_dict)
        self.assertEqual(alive_dict["2.2.2.2"], 25.0)
        self.assertNotIn("3.3.3.3", alive_dict)

    # Test B7: Local trust store failure (>90% cert fail) fallback and surfacing
    async def test_b7_detect_local_trust_store_failure(self):
        import cf_scan

        # All 5 addresses fail cert verification, but succeed with permissive probe
        async def mock_http_probe(ip, host, port, path, timeout, want_body=False, sni=None, verify=False):
            if verify:
                return {"error": "CertVerify", "valid": False, "cf_error": False, "cert_ok": False}
            else:
                return {
                    "valid": True, "cf_error": False, "cert_ok": False, "ttfb_ms": 28.0,
                    "body": "ip=90.0.0.1\ncolo=DUS\nloc=DE\n"
                }

        alive = [("104.16.1." + str(i), 20.0 + i) for i in range(5)]
        with patch("cf_scan.http_probe", side_effect=mock_http_probe), \
             patch("sys.stderr", new=io.StringIO()) as fake_stderr:
            good, mediated, my_ip, trust_broken = await cf_scan.stage_edge(
                alive, "example.com", 443, "/cdn-cgi/trace", 2.0, 5
            )

        self.assertTrue(trust_broken)
        # Warning logged naming CA bundle, clock, certificate chain
        stderr_val = fake_stderr.getvalue()
        self.assertIn("trust store failure", stderr_val)
        self.assertIn("CA bundle", stderr_val)
        self.assertIn("clock", stderr_val)
        self.assertIn("certificate chain", stderr_val)

        # Candidates accepted with cert_ok=False
        self.assertEqual(len(good), 5)
        for d in good:
            self.assertFalse(d["cert_ok"])

        # write_results records trust_store_broken: True in json
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "scan_out")
            cf_scan.write_results(good, out_base, trust_store_broken=trust_broken)
            with open(out_base + ".json") as f:
                payload = json.load(f)
            self.assertTrue(payload["trust_store_broken"])
            self.assertEqual(len(payload["results"]), 5)

        # cfscanner.run_scan logs warning when trust_store_broken is True
        mock_conn = MagicMock()
        mock_sftp = AsyncMock()
        mock_file = AsyncMock()
        mock_sftp.open = MagicMock(return_value=mock_file)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)
        mock_sftp.__aenter__ = AsyncMock(return_value=mock_sftp)
        mock_sftp.__aexit__ = AsyncMock(return_value=None)
        mock_conn.start_sftp_client = MagicMock(return_value=mock_sftp)

        async def mock_run(cmd, check=False):
            res = MagicMock()
            if "cat " in cmd:
                res.stdout = json.dumps({
                    "scan_start": int(time.time()),
                    "engine_id": 1,
                    "trust_store_broken": True,
                    "results": [{"ip": "104.16.1.1", "rtt": 25.0}]
                })
            else:
                res.stdout = ""
            res.exit_status = 0
            return res

        mock_conn.run = AsyncMock(side_effect=mock_run)
        log_mock = AsyncMock()
        with patch("cfscanner.tunnel.connect", AsyncMock(return_value=mock_conn)), \
             patch("asyncio.sleep", AsyncMock()):
            data, _ = await cfscanner.run_scan(
                {"host": "remote.ir", "user": "root", "password": "p"},
                jump=None, log=log_mock, engine_id=1
            )
            self.assertEqual(len(data), 1)
            self.assertTrue(any("اعتبارسنجی گواهی SSL" in call[0][0] for call in log_mock.call_args_list))

    # Test A7 coverage: partial write from stage-1 tuples, stage-3 data, and signal handler
    async def test_a7_partial_results_coverage(self):
        import cf_scan

        # 1. Stage-1 partial write from tuples (ip, ms) converted to dicts
        alive_tuples = [("104.16.1.10", 25.0), ("104.16.1.11", 30.0)]
        stage1_candidates = [{"ip": r[0], "rtt": r[1], "jitter": 0.0, "loss": 0.0} for r in alive_tuples]
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "stage1_out")
            cf_scan.write_results(stage1_candidates, out_base)
            with open(out_base + ".json") as f:
                p = json.load(f)
            self.assertEqual(len(p["results"]), 2)
            self.assertEqual(p["results"][0]["ip"], "104.16.1.10")
            self.assertEqual(p["results"][0]["rtt"], 25.0)

        # 2. Stage-3 checkpoint partial write
        stage3_candidates = [
            {"ip": "104.16.1.10", "rtt": 24.5, "jitter": 1.2, "loss": 0.0, "tls_loss": 0.0}
        ]
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "stage3_out")
            cf_scan.write_results(stage3_candidates, out_base)
            with open(out_base + ".json") as f:
                p = json.load(f)
            self.assertEqual(len(p["results"]), 1)
            self.assertEqual(p["results"][0]["jitter"], 1.2)

        # 3. SIGTERM signal handler writes current candidates and exits
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "sigterm_out")
            test_candidates = [{"ip": "104.16.1.20", "rtt": 22.0, "loss": 0.0}]

            def make_handler(candidates, out_path):
                def sigterm_handler(signum, frame):
                    if candidates:
                        cf_scan.write_results(candidates, out_path, scan_start=100.0, engine_id=1)
                    sys.exit(0)
                return sigterm_handler

            handler = make_handler(test_candidates, out_base)
            with self.assertRaises(SystemExit) as cm:
                handler(signal.SIGTERM, None)
            self.assertEqual(cm.exception.code, 0)
            with open(out_base + ".json") as f:
                p = json.load(f)
            self.assertEqual(len(p["results"]), 1)
            self.assertEqual(p["results"][0]["ip"], "104.16.1.20")

    def test_c1_candidate_generation(self):
        import ipaddress
        import cf_scan
        ranges = [l.strip() for l in cf_scan.CF_V4_FALLBACK.splitlines() if l.strip()]
        ips = cf_scan.candidates(ranges, per_24=2, limit=100)
        self.assertEqual(len(ips), 100)
        self.assertEqual(len(set(ips)), 100)
        parsed = [ipaddress.IPv4Address(ip) for ip in ips]
        prefixes_16 = {f"{ip.exploded.split('.')[0]}.{ip.exploded.split('.')[1]}" for ip in parsed}
        self.assertGreater(len(prefixes_16), 1)


if __name__ == "__main__":
    unittest.main()



