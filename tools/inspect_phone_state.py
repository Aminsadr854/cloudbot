#!/usr/bin/env python3
"""
Usage: python3 tools/inspect_phone_state.py /path/to/cloudbot.db

Read-only inspector for phone consensus voting state and delivery metrics.
Opens the database in read-only mode (mode=ro) and strictly sanitises all outputs:
- All IP addresses are masked to first octet (e.g. 104.x.x.x).
- No tokens, credentials, hostnames, or domains are emitted.
- Standard library only (Python 3.8+).
"""

import sys
import os
import sqlite3
import json
import hashlib
from typing import List, Dict, Any, Optional

ENCRYPTED_SETTINGS_KEYS = {
    "cf_token",
    "cfscan",
    "iran_jump",
    "sub_url",
}


def mask_ip(ip: Optional[str]) -> str:
    """Mask IP address to first octet (e.g. 104.x.x.x)."""
    if not ip or not isinstance(ip, str):
        return "none"
    parts = ip.strip().split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.x.x.x"
    # Fallback for IPv6 or malformed strings
    if ":" in ip:
        return ip.split(":")[0] + ":x"
    return "x.x.x.x"


def candidate_set_hash(ips: List[str], controls: List[str] = ()) -> str:
    """Compute candidate set hash identically to Store.candidate_set_hash."""
    ctrl_set = set(controls or [])
    cand_ips = sorted(ip for ip in (ips or []) if ip and ip not in ctrl_set)
    if not cand_ips:
        return ""
    s = ",".join(cand_ips)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tools/inspect_phone_state.py /path/to/cloudbot.db", file=sys.stderr)
        sys.exit(1)

    db_path = sys.argv[1]
    if not os.path.exists(db_path):
        print(f"Error: Database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    # Open strictly in read-only mode using sqlite3 URI
    abs_path = os.path.abspath(db_path)
    uri = f"file:{abs_path}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
    except Exception as e:
        print(f"Error connecting to database in read-only mode: {e}", file=sys.stderr)
        sys.exit(1)

    cur = con.cursor()

    # Verify read-only enforcement
    try:
        cur.execute("PRAGMA query_only = ON")
    except Exception:
        pass

    def get_setting(key: str) -> Optional[str]:
        if key in ENCRYPTED_SETTINGS_KEYS:
            print(f"ENCRYPTED: {key}")
            return None
        row = cur.execute("SELECT v FROM settings WHERE k = ?", (key,)).fetchone()
        if not row:
            return None
        val = row[0]
        # Safety check: if raw value appears to be Fernet ciphertext (starts with gAAAAA)
        if isinstance(val, str) and val.startswith("gAAAAA"):
            print(f"ENCRYPTED: {key}")
            return None
        return val

    print("================================================================================")
    print("PHONE STATE INSPECTOR (READ-ONLY)")
    print("================================================================================")

    for engine_id in (1, 2, 3):
        print(f"\n--- ENGINE {engine_id} ---")

        # 1. scan_last_decision_engine_{id}
        decision_key = f"scan_last_decision_engine_{engine_id}"
        decision_val = get_setting(decision_key)
        if decision_val is None and engine_id == 1:
            decision_val = get_setting("scan_last_decision")

        # 2. current candidate list
        cand_key = f"scan_candidates_engine_{engine_id}"
        cand_raw = get_setting(cand_key)
        if not cand_raw and engine_id == 1:
            cand_raw = get_setting("scan_candidates")
        cand_data = json.loads(cand_raw) if cand_raw else {}

        cand_ips = cand_data.get("ips") or []
        cand_controls = cand_data.get("controls") or []
        cand_ts = cand_data.get("ts") or 0
        cand_hash = candidate_set_hash(cand_ips, cand_controls)

        # 3. delivery_state_engine_{id}
        delivery_key = f"delivery_state_engine_{engine_id}"
        delivery_raw = get_setting(delivery_key)
        delivery_data = json.loads(delivery_raw) if delivery_raw else {}
        devices_delivery = delivery_data.get("devices") or {}

        # 4. device_reports_engine_{id}
        reports_key = f"device_reports_engine_{engine_id}"
        reports_raw = get_setting(reports_key)
        reports_data = json.loads(reports_raw) if reports_raw else {}
        if not reports_data:
            # Fallback to global device_reports if empty
            global_raw = get_setting("device_reports")
            if global_raw:
                try:
                    all_reps = json.loads(global_raw)
                    cand_ip_set = set(cand_ips)
                    for d, rep in all_reps.items():
                        rep_ips = {r.get("ip") for r in (rep.get("results") or []) if isinstance(r, dict)}
                        if (rep_ips & cand_ip_set) or rep.get("engine_id") == engine_id:
                            reports_data[d] = rep
                except Exception:
                    pass

        # Voters count: devices that submitted non-empty results for this round
        voters_count = sum(1 for d, r in reports_data.items() if r.get("results"))

        print(f"Decision: {decision_val or '(none)'}")
        print(f"Voter count: {voters_count}")
        print(f"Shortlist timestamp: {cand_ts}")
        print(f"Shortlist candidate count: {len(cand_ips)} addresses, {len(cand_controls)} controls")
        print(f"Shortlist candidate_set_hash: {cand_hash or '(empty)'}")

        # Delivery status per device
        print("Device delivery status:")
        if not devices_delivery:
            print("  (no delivery state recorded)")
        else:
            for dev_name, dstate in sorted(devices_delivery.items()):
                status = dstate.get("status", "PENDING")
                delivered_at = dstate.get("delivered_at", 0)
                operator = dstate.get("operator", "")
                print(f"  - Device: {dev_name} | Operator: {operator} | Status: {status} | Delivered at: {delivered_at}")

        # Device reports
        print("Device reports:")
        if not reports_data:
            print("  (no device reports recorded)")
        else:
            for dev_name, rdata in sorted(reports_data.items()):
                net_type = rdata.get("net", "unknown")
                rep_ts = rdata.get("ts", 0)
                operator = rdata.get("operator", "")
                results = rdata.get("results") or []
                res_count = len(results)

                # Check control address response
                control_set = set(cand_controls)
                control_results = [r for r in results if r.get("ip") in control_set]
                if control_results:
                    ctrl_answered = any(bool(r.get("ok")) for r in control_results)
                    ctrl_masked = [f"{mask_ip(r.get('ip'))}: ok={r.get('ok')}" for r in control_results]
                    ctrl_status_str = f"answered={ctrl_answered} ({', '.join(ctrl_masked)})"
                else:
                    ctrl_status_str = "no control address in results"

                # Hash check for latest report
                rep_ips = [r.get("ip") for r in results if r.get("ip")]
                rep_hash = candidate_set_hash(rep_ips, cand_controls)
                hash_match = (cand_hash != "" and rep_hash == cand_hash)

                print(f"  - Device: {dev_name}")
                print(f"      Operator: {operator}")
                print(f"      Network type: {net_type}")
                print(f"      Report timestamp: {rep_ts}")
                print(f"      Results count: {res_count}")
                print(f"      Control address check: {ctrl_status_str}")
                print(f"      Report candidate_set_hash: {rep_hash or '(empty)'}")
                print(f"      Hash matches current shortlist: {hash_match}")

    con.close()


if __name__ == "__main__":
    main()
