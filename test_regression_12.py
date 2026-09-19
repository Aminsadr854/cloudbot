"""
Comprehensive 12 Regression Tests for Cloudflare Scanner Bot Architecture Overhaul.
Tests:
 1. Error 1034 rejection
 2. Error 1000 rejection
 3. Valid protocol response (HTTP 400 WebSocket)
 4. Android engine isolation
 5. SNI isolation
 6. 2/2 consensus enforcement
 7. DNS API failure handling
 8. Post-DNS failure and automatic rollback
 9. Successful deployment flow
10. 3-engine isolation
11. Fake IP protection (85.9.109.98, 85.9.108.98)
12. Current live IP protection against generic candidates
"""
import asyncio
import os
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

if os.path.exists("/tmp/test_cloudbot"):
    sys.path.insert(0, "/tmp/test_cloudbot")
sys.path.insert(0, "/opt/cloudbot")
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from store import Store
import scanner_engine
import cf_scan
import cfscanner


class TestRegression12(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test.db")
        self.key_path = os.path.join(self.tmp_dir.name, "test.key")
        self.st = Store(db_path=self.db_path, key_path=self.key_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    # ----------------------------------------------------------------------
    # Test 1: Error 1034 rejection
    # ----------------------------------------------------------------------
    async def test_01_error_1034_rejection(self):
        """Candidates returning Cloudflare Error 1034 must be marked invalid and cf_error."""
        fake_body = (b"<html><head><title>Edge IP Restricted</title></head>"
                     b"<body>Error code: 1034 - Edge IP Restricted</body></html>")
        fake_head = b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n"

        reader = AsyncMock()
        reader.readuntil.return_value = fake_head
        reader.read.return_value = fake_body
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            res = await cf_scan.http_probe("1.2.3.4", "example.com", 443, "/test", 2.0, want_body=True)
            self.assertTrue(res["cf_error"])
            self.assertEqual(res["cf_err_code"], "1034")
            self.assertFalse(res["valid"])

            valid, reason = await scanner_engine.verify_domain_ip("1.2.3.4", "example.com", "example.com")
            self.assertFalse(valid)
            self.assertIn("1034", reason)

    # ----------------------------------------------------------------------
    # Test 2: Error 1000 rejection
    # ----------------------------------------------------------------------
    async def test_02_error_1000_rejection(self):
        """Candidates returning Cloudflare Error 1000 (DNS points to prohibited IP) must be rejected."""
        fake_body = (b"<html><head><title>DNS points to prohibited IP</title></head>"
                     b"<body>error code: 1000</body></html>")
        fake_head = b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n\r\n"

        reader = AsyncMock()
        reader.readuntil.return_value = fake_head
        reader.read.return_value = fake_body
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            res = await cf_scan.http_probe("1.2.3.4", "c2.domain.ir", 443, "/cdn-cgi/trace", 2.0, want_body=True)
            self.assertTrue(res["cf_error"])
            self.assertEqual(res["cf_err_code"], "1000")
            self.assertFalse(res["valid"])

            valid, reason = await scanner_engine.verify_domain_ip("1.2.3.4", "c2.domain.ir", "c2.domain.ir")
            self.assertFalse(valid)
            self.assertIn("1000", reason)

    # ----------------------------------------------------------------------
    # Test 3: Valid protocol response (HTTP 400 WebSocket)
    # ----------------------------------------------------------------------
    async def test_03_valid_protocol_websocket_response(self):
        """Backend returning HTTP 400 Bad Request with Sec-WebSocket-Version header is valid."""
        fake_head = (b"HTTP/1.1 400 Bad Request\r\n"
                     b"Server: cloudflare\r\n"
                     b"Sec-WebSocket-Version: 13\r\n\r\n")
        fake_body = b"Bad Request"

        reader = AsyncMock()
        reader.readuntil.return_value = fake_head
        reader.read.return_value = fake_body
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(reader, writer)):
            res = await cf_scan.http_probe("104.26.14.9", "cdn.domain.ir", 443, "/", 2.0, want_body=True)
            self.assertFalse(res["cf_error"])
            self.assertTrue(res["valid"])

            valid, reason = await scanner_engine.verify_domain_ip("104.26.14.9", "cdn.domain.ir", "cdn.domain.ir")
            self.assertTrue(valid)
            self.assertIn("WebSocket", reason)

    # ----------------------------------------------------------------------
    # Test 4: Android engine isolation
    # ----------------------------------------------------------------------
    def test_04_android_engine_isolation(self):
        """Device reports saved for Engine 1 must not appear in Engine 2 or Engine 3."""
        self.st.save_device_report("dev_mci", "MCI", [{"ip": "1.1.1.1", "ok": True}], net="cellular", engine_id=1)
        self.st.save_device_report("dev_mtn", "MTN", [{"ip": "2.2.2.2", "ok": True}], net="cellular", engine_id=2)

        e1_reports = self.st.device_reports(engine_id=1)
        e2_reports = self.st.device_reports(engine_id=2)
        e3_reports = self.st.device_reports(engine_id=3)

        self.assertIn("dev_mci", e1_reports)
        self.assertNotIn("dev_mtn", e1_reports)

        self.assertIn("dev_mtn", e2_reports)
        self.assertNotIn("dev_mci", e2_reports)

        self.assertEqual(len(e3_reports), 0)

    # ----------------------------------------------------------------------
    # Test 5: SNI isolation
    # ----------------------------------------------------------------------
    def test_05_sni_isolation(self):
        """Each engine must resolve its own isolated Host and SNI."""
        self.st.update_cfscan(1, fqdn="c1.dom1.com", sni="sni1.dom1.com")
        self.st.update_cfscan(2, fqdn="c2.dom2.com", host="host2.dom2.com")
        self.st.update_cfscan(3, fqdn="c3.dom3.com")

        h1, s1 = self.st.get_engine_targets(1)
        h2, s2 = self.st.get_engine_targets(2)
        h3, s3 = self.st.get_engine_targets(3)

        self.assertEqual(h1, "sni1.dom1.com")
        self.assertEqual(s1, "sni1.dom1.com")

        self.assertEqual(h2, "host2.dom2.com")
        self.assertEqual(s2, "c2.dom2.com")

        self.assertEqual(h3, "c3.dom3.com")
        self.assertEqual(s3, "c3.dom3.com")

    # ----------------------------------------------------------------------
    # Test 6: 2/2 consensus enforcement
    # ----------------------------------------------------------------------
    def test_06_two_of_two_consensus_enforcement(self):
        """Candidate requires approval from both phones (2/2) to be chosen."""
        cand_list = [
            {"ip": "104.26.1.1", "rtt": 40.0, "jitter": 2.0, "loss": 0.0},
            {"ip": "104.26.1.2", "rtt": 50.0, "jitter": 2.0, "loss": 0.0}
        ]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)

        # Case A: Only 1 phone voted
        self.st.save_device_report("dev1", "MCI", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.1.1", "ok": True, "rtt_ms": 45.0, "loss": 0.0},
            {"ip": "104.26.1.2", "ok": True, "rtt_ms": 50.0, "loss": 0.0}
        ], net="cellular", engine_id=1)
        dec_1 = scanner_engine.choose(cand_list, live_ip="1.1.1.1", engine_id=1, st=self.st)
        self.assertFalse(dec_1["change"])
        self.assertEqual(dec_1["voters"], 1)

        # Case B: 2 phones voted, but phone 2 disapproved 104.26.1.1
        self.st.save_device_report("dev2", "MTN", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.1.1", "ok": False, "rtt_ms": None, "loss": 1.0},
            {"ip": "104.26.1.2", "ok": True, "rtt_ms": 52.0, "loss": 0.0}
        ], net="cellular", engine_id=1)
        dec_2 = scanner_engine.choose(cand_list, live_ip="1.1.1.1", engine_id=1, st=self.st)
        self.assertEqual(dec_2["voters"], 2)
        # 104.26.1.1 failed dev2; only 104.26.1.2 approved by both
        self.assertIn("104.26.1.2", dec_2["needs_measure"])
        self.assertNotIn("104.26.1.1", dec_2["needs_measure"])

        # Case C: If neither approved by both
        self.st.save_device_report("dev1", "MCI", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.1.1", "ok": True, "rtt_ms": 45.0, "loss": 0.0},
            {"ip": "104.26.1.2", "ok": False, "rtt_ms": None, "loss": 1.0}
        ], net="cellular", engine_id=1)
        dec_3 = scanner_engine.choose(cand_list, live_ip="1.1.1.1", engine_id=1, st=self.st)
        self.assertFalse(dec_3["change"])
        self.assertEqual(dec_3["needs_measure"], [])
        self.assertIn("هیچ آدرسی تأیید هر دو گوشی را نگرفت", dec_3["why"])

    # ----------------------------------------------------------------------
    # Test 7: DNS API failure handling
    # ----------------------------------------------------------------------
    async def test_07_dns_api_failure_handling(self):
        """DNS update exception must be caught safely without crashing and without updating last_best_ip."""
        eng = scanner_engine.ScannerEngine(engine_id=1, store=self.st)
        self.st.update_cfscan(1, fqdn="c1.dom.ir", auto_apply=True, last_best_ip="1.1.1.1")
        self.st.set_cf_token("fake_token")

        cand_list = [{"ip": "104.26.1.1", "rtt": 40.0, "jitter": 2.0, "loss": 0.0}]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)
        self.st.save_device_report("dev1", "MCI",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "104.26.1.1", "ok": True, "rtt_ms": 40.0, "loss": 0.0}],
            net="cellular", engine_id=1)
        self.st.save_device_report("dev2", "MTN",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "104.26.1.1", "ok": True, "rtt_ms": 41.0, "loss": 0.0}],
            net="cellular", engine_id=1)

        # Mock H2H
        self.st.set_scan_h2h({
            "key": f"{self.st.scan_candidates(1)['ts']}|1.1.1.1|104.26.1.1",
            "ts": 9999999999,
            "measured": {
                "1.1.1.1": {"rtt": 100.0, "jitter": 10.0, "loss": 0.0, "valid": True},
                "104.26.1.1": {"rtt": 40.0, "jitter": 2.0, "loss": 0.0, "valid": True}
            }
        }, engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone_123"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec_123", "content": "1.1.1.1"})
        mock_cf.update_a = AsyncMock(side_effect=RuntimeError("Cloudflare API 500 Error"))

        notify_mock = AsyncMock()

        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.verify_domain_ip", AsyncMock(return_value=(True, "HTTP 200 OK"))):
            await eng.phone_recheck_pass(notify_fn=notify_mock)

        # Confirm last_best_ip was NOT changed to candidate
        cfg = self.st.cfscan(1)
        self.assertEqual(cfg.get("last_best_ip"), "1.1.1.1")
        notify_mock.assert_called()
        self.assertIn("خطای کلادفلر", notify_mock.call_args[0][0])

    # ----------------------------------------------------------------------
    # Test 8: Post-DNS failure and automatic rollback
    # ----------------------------------------------------------------------
    async def test_08_post_dns_failure_and_rollback(self):
        """If post-DNS domain verification fails, system automatically rolls back DNS to previous IP."""
        eng = scanner_engine.ScannerEngine(engine_id=1, store=self.st)
        self.st.update_cfscan(1, fqdn="c1.dom.ir", auto_apply=True, last_best_ip="1.1.1.1")
        self.st.set_cf_token("fake_token")

        cand_list = [{"ip": "104.26.1.1", "rtt": 40.0, "jitter": 2.0, "loss": 0.0}]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)
        self.st.save_device_report("dev1", "MCI",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "104.26.1.1", "ok": True, "rtt_ms": 40.0, "loss": 0.0}],
            net="cellular", engine_id=1)
        self.st.save_device_report("dev2", "MTN",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "104.26.1.1", "ok": True, "rtt_ms": 41.0, "loss": 0.0}],
            net="cellular", engine_id=1)

        # Mock H2H
        self.st.set_scan_h2h({
            "key": f"{self.st.scan_candidates(1)['ts']}|1.1.1.1|104.26.1.1",
            "ts": 9999999999,
            "measured": {
                "1.1.1.1": {"rtt": 100.0, "jitter": 10.0, "loss": 0.0, "valid": True},
                "104.26.1.1": {"rtt": 40.0, "jitter": 2.0, "loss": 0.0, "valid": True}
            }
        }, engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone_123"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec_123", "content": "1.1.1.1"})
        mock_cf.update_a = AsyncMock(return_value=True)

        notify_mock = AsyncMock()

        # verify_domain_ip: Pre-validation passes (True), but Post-validation fails (False)
        verify_side_effects = [
            (True, "HTTP 200 OK"),            # Pre-validation
            (False, "Cloudflare Error 1034")   # Post-validation
        ]

        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.verify_domain_ip", AsyncMock(side_effect=verify_side_effects)), \
             patch("asyncio.sleep", AsyncMock()):  # don't wait 6s during unit test
            await eng.phone_recheck_pass(notify_fn=notify_mock)

        # Confirm rollback call was made to previous_live_ip ("1.1.1.1")
        self.assertEqual(mock_cf.update_a.call_count, 2)
        second_call = mock_cf.update_a.call_args_list[1]
        self.assertEqual(second_call[0][2], "1.1.1.1")

        # Confirm last_best_ip remains unchanged
        cfg = self.st.cfscan(1)
        self.assertEqual(cfg.get("last_best_ip"), "1.1.1.1")
        self.assertIn("خطا در تست پس از DNS", notify_mock.call_args[0][0])

    # ----------------------------------------------------------------------
    # Test 9: Successful deployment flow
    # ----------------------------------------------------------------------
    async def test_09_successful_deployment_flow(self):
        """When pre-validation and post-validation succeed, DNS is updated and candidate is confirmed."""
        eng = scanner_engine.ScannerEngine(engine_id=1, store=self.st)
        self.st.update_cfscan(1, fqdn="c1.dom.ir", auto_apply=True, last_best_ip="1.1.1.1")
        self.st.set_cf_token("fake_token")

        cand_list = [{"ip": "104.26.14.9", "rtt": 40.0, "jitter": 2.0, "loss": 0.0}]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)
        self.st.save_device_report("dev1", "MCI",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "104.26.14.9", "ok": True, "rtt_ms": 40.0, "loss": 0.0}],
            net="cellular", engine_id=1)
        self.st.save_device_report("dev2", "MTN",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "104.26.14.9", "ok": True, "rtt_ms": 41.0, "loss": 0.0}],
            net="cellular", engine_id=1)

        self.st.set_scan_h2h({
            "key": f"{self.st.scan_candidates(1)['ts']}|1.1.1.1|104.26.14.9",
            "ts": 9999999999,
            "measured": {
                "1.1.1.1": {"rtt": 100.0, "jitter": 10.0, "loss": 0.0, "valid": True},
                "104.26.14.9": {"rtt": 40.0, "jitter": 2.0, "loss": 0.0, "valid": True}
            }
        }, engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone_123"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec_123", "content": "1.1.1.1"})
        mock_cf.update_a = AsyncMock(return_value=True)

        notify_mock = AsyncMock()

        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.verify_domain_ip", AsyncMock(return_value=(True, "Valid WebSocket Backend (HTTP 400)"))), \
             patch("asyncio.sleep", AsyncMock()):
            await eng.phone_recheck_pass(notify_fn=notify_mock)

        # Confirm update_a was called once to 104.26.14.9
        self.assertEqual(mock_cf.update_a.call_count, 1)
        self.assertEqual(mock_cf.update_a.call_args[0][2], "104.26.14.9")

        # Confirm last_best_ip is updated
        cfg = self.st.cfscan(1)
        self.assertEqual(cfg.get("last_best_ip"), "104.26.14.9")
        self.assertIn("آی‌پی دامنه عوض شد", notify_mock.call_args[0][0])

    # ----------------------------------------------------------------------
    # Test 10: 3-engine isolation
    # ----------------------------------------------------------------------
    def test_10_three_engine_isolation(self):
        """Candidate pools, shortlists, H2H caches, and statuses must be completely isolated."""
        # Pool isolation
        self.st.pool_add([{"ip": "1.1.1.1", "rtt": 50}], engine_id=1)
        self.st.pool_add([{"ip": "2.2.2.2", "rtt": 60}], engine_id=2)
        self.st.pool_add([{"ip": "3.3.3.3", "rtt": 70}], engine_id=3)

        self.assertIn("1.1.1.1", self.st.scan_pool(1)["ips"])
        self.assertNotIn("2.2.2.2", self.st.scan_pool(1)["ips"])
        self.assertIn("2.2.2.2", self.st.scan_pool(2)["ips"])
        self.assertNotIn("3.3.3.3", self.st.scan_pool(2)["ips"])
        self.assertIn("3.3.3.3", self.st.scan_pool(3)["ips"])

        # Shortlist isolation
        self.st.set_scan_candidates([{"ip": "1.1.1.1"}], engine_id=1)
        self.st.set_scan_candidates([{"ip": "2.2.2.2"}], engine_id=2)
        self.st.set_scan_candidates([{"ip": "3.3.3.3"}], engine_id=3)

        self.assertEqual(self.st.scan_candidates(1)["ips"], ["1.1.1.1"])
        self.assertEqual(self.st.scan_candidates(2)["ips"], ["2.2.2.2"])
        self.assertEqual(self.st.scan_candidates(3)["ips"], ["3.3.3.3"])

        # Status isolation
        self.st.set_engine_status(1, "scanning", "engine 1 scanning")
        self.st.set_engine_status(2, "testing", "engine 2 testing")
        self.st.set_engine_status(3, "idle", "engine 3 idle")

        self.assertEqual(self.st.engine_status(1)["state"], "scanning")
        self.assertEqual(self.st.engine_status(2)["state"], "testing")
        self.assertEqual(self.st.engine_status(3)["state"], "idle")

    # ----------------------------------------------------------------------
    # Test 11: Fake IP protection (85.9.109.98, 85.9.108.98)
    # ----------------------------------------------------------------------
    def test_11_fake_ip_protection(self):
        """Unscanned Cloudflare DNS A-records must never be treated as discovered or best IPs."""
        cand_list = [{"ip": "104.26.1.1", "rtt": 40.0, "jitter": 2.0, "loss": 0.0}]
        # live_ip is 85.9.109.98 (not present in cand_list)
        dec = scanner_engine.choose(cand_list, live_ip="85.9.109.98", engine_id=2, st=self.st)
        self.assertIsNone(dec.get("entry"))
        self.assertFalse(dec["change"])

    # ----------------------------------------------------------------------
    # Test 12: Current live IP protection against generic candidates
    # ----------------------------------------------------------------------
    def test_12_current_live_ip_protection_against_generic_candidates(self):
        """A candidate that fails domain verification (cf_error or valid=False) cannot replace live IP."""
        cand_list = [{"ip": "162.159.128.61", "rtt": 15.0, "jitter": 1.0, "loss": 0.0}]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)
        self.st.save_device_report("dev1", "MCI",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "162.159.128.61", "ok": True, "rtt_ms": 15.0, "loss": 0.0}],
            net="cellular", engine_id=1)
        self.st.save_device_report("dev2", "MTN",
            [{"ip": "8.8.8.8", "ok": True}, {"ip": "162.159.128.61", "ok": True, "rtt_ms": 16.0, "loss": 0.0}],
            net="cellular", engine_id=1)

        # In H2H, candidate 162.159.128.61 has cf_error=True (e.g. Error 1034)
        measured = {
            "104.26.14.9": {"rtt": 40.0, "jitter": 2.0, "loss": 0.0, "valid": True, "cf_error": False},
            "162.159.128.61": {"rtt": 15.0, "jitter": 1.0, "loss": 0.0, "valid": False, "cf_error": True}
        }
        dec = scanner_engine.choose(cand_list, live_ip="104.26.14.9", measured=measured, engine_id=1, st=self.st)
        # Decision must NOT change because candidate is invalid!
        self.assertFalse(dec["change"])
        self.assertIn("هیچ‌کدام از آدرس فعلی بهتر نبود", dec["why"])

    # ----------------------------------------------------------------------
    # Test 13: Target resolution and host precedence
    # ----------------------------------------------------------------------
    def test_13_target_resolution_and_precedence(self):
        """All 3 engines resolve Host and SNI to stored probe_sni when explicit values are absent."""
        self.st.set("probe_sni", "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")
        self.st.update_cfscan(1, fqdn="c1c1c1c1c1c1.rjwarehousing.ir")
        self.st.update_cfscan(2, fqdn="c2c2c2c2c2.rjwarehousing.ir")
        self.st.update_cfscan(3, fqdn="c3c3c3c3.rjwarehousing.ir")

        h1, s1 = self.st.get_engine_targets(1)
        h2, s2 = self.st.get_engine_targets(2)
        h3, s3 = self.st.get_engine_targets(3)

        self.assertEqual(h1, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")
        self.assertEqual(s1, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")
        self.assertEqual(h2, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")
        self.assertEqual(s2, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")
        self.assertEqual(h3, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")
        self.assertEqual(s3, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")

        # Explicit host override takes priority
        self.st.update_cfscan(1, host="custom-override.rjwarehousing.ir")
        h1_over, s1_over = self.st.get_engine_targets(1)
        self.assertEqual(h1_over, "custom-override.rjwarehousing.ir")
        self.assertEqual(s1_over, "cdcdcdcdcdcddccccddddnnn.rjwarehousing.ir")

    # ----------------------------------------------------------------------
    # Test 14: Contender fallback on domain prevalidation failure
    # ----------------------------------------------------------------------
    async def test_14_contender_fallback_on_domain_prevalidation_failure(self):
        """When contender #1 fails domain prevalidation, contender #2 is evaluated and deployed."""
        eng = scanner_engine.ScannerEngine(engine_id=1, store=self.st)
        self.st.update_cfscan(1, fqdn="c1.dom.ir", auto_apply=True, last_best_ip="1.1.1.1")
        self.st.set_cf_token("fake_token")

        cand_list = [
            {"ip": "104.26.14.1", "rtt": 30.0, "jitter": 1.0, "loss": 0.0},
            {"ip": "104.26.14.2", "rtt": 35.0, "jitter": 1.0, "loss": 0.0}
        ]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)
        self.st.save_device_report("dev1", "MCI", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.14.1", "ok": True, "rtt_ms": 30.0, "loss": 0.0},
            {"ip": "104.26.14.2", "ok": True, "rtt_ms": 35.0, "loss": 0.0}
        ], net="cellular", engine_id=1)
        self.st.save_device_report("dev2", "MTN", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.14.1", "ok": True, "rtt_ms": 31.0, "loss": 0.0},
            {"ip": "104.26.14.2", "ok": True, "rtt_ms": 36.0, "loss": 0.0}
        ], net="cellular", engine_id=1)

        self.st.set_scan_h2h({
            "key": f"{self.st.scan_candidates(1)['ts']}|1.1.1.1|104.26.14.1,104.26.14.2",
            "ts": 9999999999,
            "measured": {
                "1.1.1.1": {"rtt": 100.0, "jitter": 10.0, "loss": 0.0, "valid": True},
                "104.26.14.1": {"rtt": 30.0, "jitter": 1.0, "loss": 0.0, "valid": True},
                "104.26.14.2": {"rtt": 35.0, "jitter": 1.0, "loss": 0.0, "valid": True}
            }
        }, engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone_123"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec_123", "content": "1.1.1.1"})
        mock_cf.update_a = AsyncMock(return_value=True)

        notify_mock = AsyncMock()

        async def mock_verify(ip, host=None, sni=None):
            if ip == "104.26.14.1":
                return False, "Cloudflare Error 1000"
            if ip == "104.26.14.2":
                return True, "Valid WebSocket Backend (HTTP 400)"
            return False, "Unknown IP"

        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.verify_domain_ip", side_effect=mock_verify), \
             patch("asyncio.sleep", AsyncMock()):
            await eng.phone_recheck_pass(notify_fn=notify_mock)

        # Confirm update_a was called with 104.26.14.2 (contender #2), NOT 104.26.14.1
        self.assertEqual(mock_cf.update_a.call_count, 1)
        self.assertEqual(mock_cf.update_a.call_args[0][2], "104.26.14.2")

        # Confirm last_best_ip updated to 104.26.14.2
        cfg = self.st.cfscan(1)
        self.assertEqual(cfg.get("last_best_ip"), "104.26.14.2")

    # ----------------------------------------------------------------------
    # Test 15: All contenders fail domain prevalidation - no DNS update
    # ----------------------------------------------------------------------
    async def test_15_all_contenders_fail_domain_prevalidation_no_dns_update(self):
        """When all contenders fail domain prevalidation, DNS is never updated and live IP is untouched."""
        eng = scanner_engine.ScannerEngine(engine_id=1, store=self.st)
        self.st.update_cfscan(1, fqdn="c1.dom.ir", auto_apply=True, last_best_ip="1.1.1.1")
        self.st.set_cf_token("fake_token")

        cand_list = [
            {"ip": "104.26.14.1", "rtt": 30.0, "jitter": 1.0, "loss": 0.0},
            {"ip": "104.26.14.2", "rtt": 35.0, "jitter": 1.0, "loss": 0.0}
        ]
        self.st.set_scan_candidates(cand_list, controls=["8.8.8.8"], engine_id=1)
        self.st.save_device_report("dev1", "MCI", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.14.1", "ok": True, "rtt_ms": 30.0, "loss": 0.0},
            {"ip": "104.26.14.2", "ok": True, "rtt_ms": 35.0, "loss": 0.0}
        ], net="cellular", engine_id=1)
        self.st.save_device_report("dev2", "MTN", [
            {"ip": "8.8.8.8", "ok": True},
            {"ip": "104.26.14.1", "ok": True, "rtt_ms": 31.0, "loss": 0.0},
            {"ip": "104.26.14.2", "ok": True, "rtt_ms": 36.0, "loss": 0.0}
        ], net="cellular", engine_id=1)

        self.st.set_scan_h2h({
            "key": f"{self.st.scan_candidates(1)['ts']}|1.1.1.1|104.26.14.1,104.26.14.2",
            "ts": 9999999999,
            "measured": {
                "1.1.1.1": {"rtt": 100.0, "jitter": 10.0, "loss": 0.0, "valid": True},
                "104.26.14.1": {"rtt": 30.0, "jitter": 1.0, "loss": 0.0, "valid": True},
                "104.26.14.2": {"rtt": 35.0, "jitter": 1.0, "loss": 0.0, "valid": True}
            }
        }, engine_id=1)

        mock_cf = MagicMock()
        mock_cf.zone_for = AsyncMock(return_value=["zone_123"])
        mock_cf.find_a_record = AsyncMock(return_value={"id": "rec_123", "content": "1.1.1.1"})
        mock_cf.update_a = AsyncMock(return_value=True)

        notify_mock = AsyncMock()

        # Both candidates fail domain prevalidation
        with patch("scanner_engine.Cloudflare", return_value=mock_cf), \
             patch("scanner_engine.verify_domain_ip", AsyncMock(return_value=(False, "Cloudflare Error 1000"))), \
             patch("asyncio.sleep", AsyncMock()):
            await eng.phone_recheck_pass(notify_fn=notify_mock)

        # Confirm update_a was NEVER called
        self.assertEqual(mock_cf.update_a.call_count, 0)

        # Confirm live IP untouched
        cfg = self.st.cfscan(1)
        self.assertEqual(cfg.get("last_best_ip"), "1.1.1.1")

        # Confirm decision stored
        decision = self.st.get("scan_last_decision_engine_1")
        self.assertIn("هیچ‌کدام از 2 کاندید برتر در تست اعتبارسنجی دامنه تأیید نشدند", decision)


if __name__ == "__main__":
    unittest.main()
