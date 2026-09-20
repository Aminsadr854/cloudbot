from typing import Optional
"""
Storage for the cloud-provisioning bot.

Two kinds of secret live here and both are encrypted at rest: the provider API
tokens (Linode / Vultr), and the proxies the bot reaches each account through.
A single file holding plaintext tokens for every cloud account would be a
worse leak than the servers themselves, so the key sits in its own root-only
file and the database on its own is useless.
"""
import os
import sqlite3
import time

from cryptography.fernet import Fernet

DB_PATH = os.environ.get("CLOUDBOT_DB", "/opt/cloudbot/data/cloudbot.db")
KEY_PATH = os.environ.get("CLOUDBOT_KEY", "/opt/cloudbot/data/secret.key")

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    label     TEXT NOT NULL,
    provider  TEXT NOT NULL,          -- 'linode' | 'vultr'
    token     BLOB NOT NULL,          -- encrypted API token
    proxy     BLOB,                   -- encrypted host:port:user:pass, or NULL
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,          -- 'gre' | 'paytun' | 'forward'
    iran_host  TEXT,
    foreign_host TEXT,
    ports      TEXT,                   -- comma-separated
    detail     BLOB NOT NULL,          -- encrypted JSON: creds, dev name, subnet, etc.
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS server_secrets (
    account_id  INTEGER NOT NULL,
    server_id   TEXT NOT NULL,
    root_pass   BLOB NOT NULL,          -- encrypted root password set at creation
    PRIMARY KEY (account_id, server_id)
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def _fernet(key_path=None):
    kp = key_path or os.environ.get("CLOUDBOT_KEY", KEY_PATH)
    if not os.path.exists(kp):
        os.makedirs(os.path.dirname(kp), exist_ok=True)
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    with open(kp, "rb") as f:
        return Fernet(f.read())


class Store:
    def __init__(self, db_path=None, key_path=None):
        self.db_path = db_path or os.environ.get("CLOUDBOT_DB", DB_PATH)
        self.key_path = key_path or os.environ.get("CLOUDBOT_KEY", KEY_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.con = sqlite3.connect(self.db_path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        self.f = _fernet(self.key_path)

    def close(self):
        try:
            self.con.close()
        except Exception:
            pass

    # ---- accounts ------------------------------------------------------
    def add_account(self, label, provider, token, proxy=None):
        self.con.execute(
            "INSERT INTO accounts (label, provider, token, proxy, created_at)"
            " VALUES (?,?,?,?,?)",
            (label, provider, self.f.encrypt(token.encode()),
             self.f.encrypt(proxy.encode()) if proxy else None, int(time.time())))
        self.con.commit()
        return self.con.execute("SELECT last_insert_rowid()").fetchone()[0]

    def delete_account(self, acc_id):
        n = self.con.execute("DELETE FROM accounts WHERE id = ?", (acc_id,)).rowcount
        self.con.commit()
        return n

    def set_proxy(self, acc_id, proxy):
        """Set, change, or clear (proxy=None) an account's proxy."""
        self.con.execute(
            "UPDATE accounts SET proxy = ? WHERE id = ?",
            (self.f.encrypt(proxy.encode()) if proxy else None, acc_id))
        self.con.commit()

    def _row(self, r):
        return {
            "id": r["id"], "label": r["label"], "provider": r["provider"],
            "token": self.f.decrypt(r["token"]).decode(),
            "proxy": self.f.decrypt(r["proxy"]).decode() if r["proxy"] else None,
            "created_at": r["created_at"],
        }

    def accounts(self):
        return [self._row(r) for r in
                self.con.execute("SELECT * FROM accounts ORDER BY id")]

    def account(self, acc_id):
        r = self.con.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
        return self._row(r) if r else None

    # ---- server root passwords (set at creation, needed for node-it) ---
    def set_server_pass(self, account_id, server_id, root_pass):
        # Linode never returns the root password again, so a server the bot
        # created is the only one it can SSH into to run the node install.
        self.con.execute(
            "INSERT OR REPLACE INTO server_secrets (account_id, server_id, root_pass)"
            " VALUES (?,?,?)",
            (account_id, str(server_id), self.f.encrypt(root_pass.encode())))
        self.con.commit()

    def server_pass(self, account_id, server_id):
        r = self.con.execute(
            "SELECT root_pass FROM server_secrets WHERE account_id = ? AND server_id = ?",
            (account_id, str(server_id))).fetchone()
        return self.f.decrypt(r["root_pass"]).decode() if r else None

    def forget_server(self, account_id, server_id):
        self.con.execute(
            "DELETE FROM server_secrets WHERE account_id = ? AND server_id = ?",
            (account_id, str(server_id)))
        self.con.commit()

    # ---- tunnels -------------------------------------------------------
    def add_tunnel(self, kind, iran_host, foreign_host, ports, detail: dict):
        import json
        cur = self.con.execute(
            "INSERT INTO tunnels (kind, iran_host, foreign_host, ports, detail, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (kind, iran_host, foreign_host, ports,
             self.f.encrypt(json.dumps(detail).encode()), int(time.time())))
        self.con.commit()
        return cur.lastrowid

    def tunnels(self):
        import json
        out = []
        for r in self.con.execute("SELECT * FROM tunnels ORDER BY id"):
            d = dict(r)
            d["detail"] = json.loads(self.f.decrypt(r["detail"]).decode())
            out.append(d)
        return out

    def tunnel(self, tid):
        return next((t for t in self.tunnels() if t["id"] == tid), None)

    def delete_tunnel(self, tid):
        self.con.execute("DELETE FROM tunnels WHERE id = ?", (tid,))
        self.con.commit()

    # ---- Iran jump host (encrypted) ------------------------------------
    def set_jump(self, host, port, user, password):
        import json
        self.set("iran_jump", self.f.encrypt(json.dumps(
            {"host": host, "port": port, "user": user, "password": password}
        ).encode()).decode())

    def jump(self):
        import json
        v = self.get("iran_jump")
        return json.loads(self.f.decrypt(v.encode()).decode()) if v else None

    # ---- cloudflare token (encrypted, single) --------------------------
    def set_cf_token(self, token):
        self.set("cf_token", self.f.encrypt(token.encode()).decode())

    def cf_token(self):
        v = self.get("cf_token")
        return self.f.decrypt(v.encode()).decode() if v else None

    # ---- clean-IP scanner config (encrypted; holds the scan server SSH) -
    def set_cfscan(self, cfg: dict, engine_id: int = 1):
        import json
        key = f"cfscan_engine_{engine_id}"
        enc = self.f.encrypt(json.dumps(cfg).encode()).decode()
        self.set(key, enc)
        if engine_id == 1:
            self.set("cfscan", enc)

    def cfscan(self, engine_id: int = 1) -> dict:
        import json
        key = f"cfscan_engine_{engine_id}"
        v = self.get(key)
        if not v and engine_id == 1:
            v = self.get("cfscan")
        if v:
            try:
                return json.loads(self.f.decrypt(v.encode()).decode())
            except Exception:
                pass
        # Default configuration for Engine 2 or 3: inherit scan server (ssh),
        # interval_hours, and auto_apply from Engine 1 by default, but maintain
        # separate domain and result states.
        if engine_id != 1:
            base = self.cfscan(engine_id=1)
            return {
                "ssh": base.get("ssh"),
                "interval_hours": base.get("interval_hours", 6),
                "auto_apply": base.get("auto_apply", False),
                "zone_id": None,
                "zone_name": None,
                "fqdn": None,
                "last_scan_ts": 0,
                "last_best_ip": None,
                "last_best": None,
            }
        return {}

    def update_cfscan(self, engine_id: int = 1, **fields):
        engine_id = fields.pop("engine_id", engine_id)
        cfg = self.cfscan(engine_id=engine_id)
        cfg.update(fields)
        self.set_cfscan(cfg, engine_id=engine_id)
        return cfg

    def add_found_ip(self, entry: dict, keep=20, engine_id: int = 1):
        """Record a newly chosen best IP (metrics only, no secrets)."""
        import json, time
        engine_id = entry.get("engine_id", engine_id)
        hist = self.found_ips(engine_id=engine_id)
        entry = {**entry, "ts": int(time.time()), "engine_id": engine_id}
        hist.insert(0, entry)
        key = f"cfscan_found_engine_{engine_id}"
        self.set(key, json.dumps(hist[:keep]))
        if engine_id == 1:
            self.set("cfscan_found", json.dumps(hist[:keep]))

    def found_ips(self, engine_id: int = 1) -> list:
        import json
        key = f"cfscan_found_engine_{engine_id}"
        v = self.get(key)
        if not v and engine_id == 1:
            v = self.get("cfscan_found")
        return json.loads(v) if v else []

    def get_engine_targets(self, engine_id: int = 1) -> tuple[str, str]:
        """Returns (host, sni) for a specific engine, fully isolated."""
        cfg = self.cfscan(engine_id)
        fqdn = (cfg.get("fqdn") or "").strip()
        explicit_sni = (cfg.get("sni") or "").strip()
        explicit_host = (cfg.get("host") or "").strip()
        stored_probe_sni = (self.get("probe_sni") or "").strip()

        sni = explicit_sni or stored_probe_sni or fqdn or "speed.cloudflare.com"
        host = explicit_host or explicit_sni or stored_probe_sni or fqdn
        return host, sni

    # ---- subscription link (encrypted: it is a bearer secret) ----------
    def set_sub_url(self, url):
        self.set("sub_url", self.f.encrypt(url.encode()).decode())

    def sub_url(self):
        v = self.get("sub_url")
        return self.f.decrypt(v.encode()).decode() if v else None

    # ---- repairs parked awaiting the owner or a new account ------------
    # When every account of the needed provider is gone, the repair cannot
    # finish and must not be silently dropped: it is parked here so it can be
    # resumed the moment an account appears, without the outage being forgotten.
    def add_pending(self, entry: dict):
        import json, time
        rows = self.pending()
        entry["id"] = max([r["id"] for r in rows], default=0) + 1
        entry.setdefault("created_ts", int(time.time()))
        rows.append(entry)
        self.set("pending_repairs", json.dumps(rows))
        return entry["id"]

    def pending(self) -> list:
        import json
        v = self.get("pending_repairs")
        return json.loads(v) if v else []

    def update_pending(self, pid, **fields):
        import json
        rows = self.pending()
        for r in rows:
            if r["id"] == pid:
                r.update(fields)
        self.set("pending_repairs", json.dumps(rows))

    def delete_pending(self, pid):
        import json
        self.set("pending_repairs",
                 json.dumps([r for r in self.pending() if r["id"] != pid]))

    # ---- endpoint watchdog ---------------------------------------------
    # Targets are host/port/label only - nothing secret - so they stay plain
    # JSON and can be read straight out of the database when debugging.
    def add_watch(self, target: dict):
        import json
        rows = self.watch_targets()
        target["id"] = (max([t["id"] for t in rows], default=0) + 1)
        rows.append(target)
        self.set("watch_targets", json.dumps(rows))
        return target["id"]

    def watch_targets(self) -> list:
        import json
        v = self.get("watch_targets")
        return json.loads(v) if v else []

    def update_watch(self, tid, **fields):
        import json
        rows = self.watch_targets()
        for t in rows:
            if t["id"] == tid:
                t.update(fields)
        self.set("watch_targets", json.dumps(rows))

    def delete_watch(self, tid):
        import json
        rows = [t for t in self.watch_targets() if t["id"] != tid]
        self.set("watch_targets", json.dumps(rows))
        state = self.watch_state()
        state.pop(str(tid), None)
        self.set_watch_state(state)

    def watch_cfg(self) -> dict:
        import json
        v = self.get("watch_cfg")
        d = json.loads(v) if v else {}
        d.setdefault("enabled", False)
        d.setdefault("interval_minutes", 15)
        d.setdefault("last_ts", 0)
        d.setdefault("sub_sync_ts", 0)     # daily re-read of the subscription
        d.setdefault("auto_replace", False)  # rebuilding servers costs money: opt-in
        return d

    def set_watch_cfg(self, **fields):
        import json
        cfg = self.watch_cfg()
        cfg.update(fields)
        self.set("watch_cfg", json.dumps(cfg))
        return cfg

    def replace_watch_targets(self, rows: list):
        """Write the whole target list back (used by the daily sub re-sync)."""
        import json
        self.set("watch_targets", json.dumps(rows))

    def watch_state(self) -> dict:
        import json
        v = self.get("watch_state")
        return json.loads(v) if v else {}

    def set_watch_state(self, state: dict):
        import json
        self.set("watch_state", json.dumps(state))

    def watch_last(self) -> list:
        import json
        v = self.get("watch_last")
        return json.loads(v) if v else []

    def set_watch_last(self, results: list):
        import json
        self.set("watch_last", json.dumps(results))

    # ---- phone probes -------------------------------------------------
    # A relay measures one operator's view of an IP. Phones on other operators
    # see a different one, and an address that is only clean where the relay
    # sits is not clean for the customers. These tables hold what the phones
    # were asked to test and what they found.
    def set_scan_candidates(self, entries: list, controls=None, keep=45, engine_id: int = 1):
        """
        The shortlist handed to the phones, with the relay's own numbers kept.
        Isolated strictly per engine: scan_candidates_engine_{engine_id}.
        """
        import json, time
        ips, metrics = [], {}
        for e in list(entries)[:keep]:
            if isinstance(e, str):
                ip = e
            else:
                ip = e.get("ip")
                if ip:
                    metrics[ip] = {k: v for k, v in e.items() if k != "ip"}
            if ip:
                ips.append(ip)
        payload = {
            "ts": int(time.time()), "engine_id": engine_id, "ips": ips, "metrics": metrics,
            "controls": [c for c in (controls or []) if c]
        }
        key = f"scan_candidates_engine_{engine_id}"
        self.set(key, json.dumps(payload))
        # Keep legacy pointer updated only for engine 1
        if engine_id == 1:
            self.set("scan_candidates", json.dumps(payload))
        # Initialize delivery lifecycle state for this shortlist
        self.init_delivery_state(engine_id, payload["ts"], ips, payload["controls"])

    def set_candidate_meta(self, engine_id: int = 1, **fields):
        """Bookkeeping that rides with the shortlist for a specific engine."""
        import json
        engine_id = fields.pop("engine_id", engine_id)
        key = f"scan_candidates_engine_{engine_id}"
        v = self.get(key)
        d = json.loads(v) if v else {}
        d.update(fields)
        self.set(key, json.dumps(d))

    SHORTLIST_DELIVERY_TTL = 3 * 3600  # 3 hours delivery window for phones to poll

    @staticmethod
    def candidate_set_hash(ips: list, controls: list = ()) -> str:
        import hashlib
        ctrl_set = set(controls or [])
        cand_ips = sorted(ip for ip in (ips or []) if ip and ip not in ctrl_set)
        if not cand_ips:
            return ""
        s = ",".join(cand_ips)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]

    def init_delivery_state(self, engine_id: int, cand_ts: int, ips: list, controls: list = ()):
        import json
        cand_hash = self.candidate_set_hash(ips, controls)
        state = {
            "engine_id": engine_id,
            "shortlist_timestamp": cand_ts,
            "candidate_set_hash": cand_hash,
            "candidate_count": len(ips),
            "created_at": cand_ts,
            "expires_at": cand_ts + self.SHORTLIST_DELIVERY_TTL if cand_ts else 0,
            "devices": {},
            "delivery_complete": False
        }
        self.set(f"delivery_state_engine_{engine_id}", json.dumps(state))
        return state

    def get_delivery_state(self, engine_id: int) -> dict:
        import json, time
        key = f"delivery_state_engine_{engine_id}"
        v = self.get(key)
        cand = self.scan_candidates(engine_id=engine_id)
        cand_ts = cand.get("ts", 0)
        cand_ips = cand.get("ips", [])
        controls = cand.get("controls", [])
        cand_hash = self.candidate_set_hash(cand_ips, controls)

        state = json.loads(v) if v else {}
        if not state or state.get("shortlist_timestamp") != cand_ts or state.get("candidate_set_hash") != cand_hash:
            state = {
                "engine_id": engine_id,
                "shortlist_timestamp": cand_ts,
                "candidate_set_hash": cand_hash,
                "candidate_count": len(cand_ips),
                "created_at": cand_ts,
                "expires_at": cand_ts + self.SHORTLIST_DELIVERY_TTL if cand_ts else 0,
                "devices": {},
                "delivery_complete": False
            }

        # Sync from device reports
        reports = self.device_reports(engine_id=engine_id)
        complete_count = 0
        for dev_id, rep in reports.items():
            rep_ts = rep.get("ts", 0)
            rep_res = rep.get("results") or []
            rep_ips = [r.get("ip") for r in rep_res if r.get("ip")]
            rep_hash = self.candidate_set_hash(rep_ips, controls)
            dev_state = state["devices"].setdefault(dev_id, {})
            dev_state["device_id"] = dev_id
            dev_state["operator"] = rep.get("operator", "")
            dev_state["reported_at"] = rep_ts
            dev_state["report_candidate_set_hash"] = rep_hash
            is_match = (rep_hash == cand_hash) and bool(cand_hash)
            is_fresh = is_match and (rep_ts >= cand_ts)
            dev_state["report_fresh"] = is_fresh
            if is_fresh:
                dev_state["status"] = "COMPLETE"
                complete_count += 1
            elif dev_state.get("status") != "DELIVERED":
                dev_state["status"] = "PENDING"

        if complete_count >= 2:
            state["delivery_complete"] = True

        self.set(key, json.dumps(state))
        return state

    def record_candidate_delivery(self, engine_id: int, device: str, operator: str = ""):
        import json, time
        if not device:
            return
        state = self.get_delivery_state(engine_id)
        dev_state = state["devices"].setdefault(device, {})
        dev_state["device_id"] = device
        if operator:
            dev_state["operator"] = operator
        dev_state["delivered_at"] = int(time.time())
        if dev_state.get("status") != "COMPLETE":
            dev_state["status"] = "DELIVERED"
        key = f"delivery_state_engine_{engine_id}"
        self.set(key, json.dumps(state))

    def record_candidate_report(self, engine_id: int, device: str, operator: str, reported_ips: list):
        import json, time
        if not device:
            return
        state = self.get_delivery_state(engine_id)
        cand = self.scan_candidates(engine_id=engine_id)
        cand_ts = cand.get("ts", 0)
        cand_hash = state.get("candidate_set_hash", "")
        controls = cand.get("controls", [])
        rep_hash = self.candidate_set_hash(reported_ips, controls)

        dev_state = state["devices"].setdefault(device, {})
        dev_state["device_id"] = device
        dev_state["operator"] = operator
        dev_state["reported_at"] = int(time.time())
        dev_state["report_candidate_set_hash"] = rep_hash
        is_match = (rep_hash == cand_hash) and bool(cand_hash)
        is_fresh = is_match and (dev_state["reported_at"] >= cand_ts)
        dev_state["report_fresh"] = is_fresh
        if is_fresh:
            dev_state["status"] = "COMPLETE"

        complete_count = sum(1 for d in state["devices"].values() if d.get("status") == "COMPLETE")
        if complete_count >= 2:
            state["delivery_complete"] = True

        key = f"delivery_state_engine_{engine_id}"
        self.set(key, json.dumps(state))

    def active_probe_engine(self, device: Optional[str] = None, operator: Optional[str] = None) -> int:
        """
        Find which engine currently needs candidate delivery.
        Considers:
        - shortlist timestamp and expiration (SHORTLIST_DELIVERY_TTL)
        - per-device delivery and completion state
        - candidate set hash matching
        - oldest pending shortlist with outstanding required devices
        """
        import time
        now = time.time()
        engine_states = {}
        for eid in (1, 2, 3):
            state = self.get_delivery_state(eid)
            cand_ts = state.get("shortlist_timestamp", 0)
            cand_count = state.get("candidate_count", 0)
            expires_at = state.get("expires_at", 0)
            if cand_ts > 0 and cand_count > 0:
                is_expired = expires_at and (now > expires_at)
                engine_states[eid] = (state, is_expired)

        if not engine_states:
            return 1

        active_states = {eid: st for eid, (st, exp) in engine_states.items() if not exp}
        if not active_states:
            active_states = {eid: st for eid, (st, exp) in engine_states.items()}

        def _device_matches(target_key: str, dev_id: str, op: str) -> bool:
            if not target_key:
                return False
            if dev_id and target_key.lower() == dev_id.lower():
                return True
            tk_low = target_key.lower()
            if op:
                op_low = op.lower()
                if "mci" in op_low and "mci" in tk_low:
                    return True
                if ("irancell" in op_low or "mtn" in op_low) and ("irancell" in tk_low or "mtn" in tk_low):
                    return True
            if dev_id:
                dev_low = dev_id.lower()
                if "mci" in dev_low and "mci" in tk_low:
                    return True
                if ("irancell" in dev_low or "mtn" in dev_low) and ("irancell" in tk_low or "mtn" in tk_low):
                    return True
            return False

        # 1. Device-aware selection: If device or operator is known
        if device or operator:
            pending_for_this_device = []
            for eid, state in active_states.items():
                if state.get("delivery_complete"):
                    continue
                dev_completed = False
                for d_id, d_info in state.get("devices", {}).items():
                    if _device_matches(d_id, device, operator) or _device_matches(d_info.get("operator", ""), device, operator):
                        if d_info.get("status") == "COMPLETE":
                            dev_completed = True
                            break
                if not dev_completed:
                    cand_ts = state.get("shortlist_timestamp", 0)
                    pending_for_this_device.append((eid, cand_ts))

            if pending_for_this_device:
                # Prefer the oldest pending shortlist that still needs this device
                pending_for_this_device.sort(key=lambda x: x[1])
                return pending_for_this_device[0][0]

        # 2. General selection: Find engines whose delivery is not complete (< 2 phones tested)
        incomplete_engines = []
        for eid, state in active_states.items():
            if not state.get("delivery_complete"):
                cand_ts = state.get("shortlist_timestamp", 0)
                incomplete_engines.append((eid, cand_ts))

        if incomplete_engines:
            # Prefer the oldest pending shortlist
            incomplete_engines.sort(key=lambda x: x[1])
            return incomplete_engines[0][0]

        # 3. All active engines are delivery-complete: return the engine with newest shortlist
        return max(active_states.keys(), key=lambda eid: active_states[eid].get("shortlist_timestamp", 0))

    def scan_candidates(self, engine_id=None) -> dict:
        import json
        if engine_id is None:
            engine_id = self.active_probe_engine()
        key = f"scan_candidates_engine_{engine_id}"
        v = self.get(key)
        if not v and engine_id == 1:
            v_legacy = self.get("scan_candidates")
            if v_legacy:
                try:
                    loaded = json.loads(v_legacy)
                    if loaded.get("engine_id") in (1, None):
                        v = v_legacy
                except Exception:
                    pass
        d = json.loads(v) if v else {}
        return {"ts": d.get("ts", 0), "engine_id": d.get("engine_id", engine_id or 1),
                "ips": d.get("ips", []),
                "metrics": d.get("metrics", {}),
                "controls": d.get("controls", []),
                "tried": d.get("tried", []),
                "reshortlists": int(d.get("reshortlists") or 0)}

    # ---- the rolling pool the continuous scan fills --------------------
    # The relay measures around the clock; every result lands here, and once a
    # window closes the best of them become the shortlist the phones judge.
    # Keeping the pool rather than the last scan's output is the difference
    # between "the best of the last minute" and "the best of the last six
    # hours", which is what the whole cycle is supposed to mean.
    def pool_add(self, entries: list, keep=200, engine_id: int = 1):
        import json, time
        pool = self.scan_pool(engine_id=engine_id)
        seen = pool.get("ips") or {}
        now = int(time.time())
        for e in entries:
            ip = e.get("ip")
            if not ip or not isinstance(e.get("rtt"), (int, float)):
                continue
            # The newest measurement wins: an address that has since gone bad
            # should not be remembered by its best moment.
            seen[ip] = {**{k: v for k, v in e.items() if k != "ip"}, "ts": now}
        if len(seen) > keep:
            def rank(kv):
                m = kv[1]
                return ((m.get("rtt") or 999) + 2 * (m.get("jitter") or 0)
                        + 1000 * (m.get("loss") or 0))
            seen = dict(sorted(seen.items(), key=rank)[:keep])
        pool["ips"] = seen
        pool.setdefault("started", now)
        pool["passes"] = int(pool.get("passes") or 0) + 1
        key = f"scan_pool_engine_{engine_id}"
        self.set(key, json.dumps(pool))
        if engine_id == 1:
            self.set("scan_pool", json.dumps(pool))

    def scan_pool(self, engine_id: int = 1) -> dict:
        import json
        key = f"scan_pool_engine_{engine_id}"
        v = self.get(key)
        if not v and engine_id == 1:
            v = self.get("scan_pool")
        d = json.loads(v) if v else {}
        return {"started": d.get("started") or 0, "ips": d.get("ips") or {},
                "passes": int(d.get("passes") or 0)}

    def pool_reset(self, engine_id: int = 1):
        import json, time
        payload = {"started": int(time.time()), "ips": {}, "passes": 0}
        key = f"scan_pool_engine_{engine_id}"
        self.set(key, json.dumps(payload))
        if engine_id == 1:
            self.set("scan_pool", json.dumps(payload))

    # ---- head-to-head cached measurements per engine -------------------
    def scan_h2h(self, engine_id: int = 1) -> dict:
        import json
        key = f"scan_h2h_engine_{engine_id}"
        v = self.get(key)
        if not v and engine_id == 1:
            v = self.get("scan_h2h")
        return json.loads(v) if v else {}

    def set_scan_h2h(self, data: dict, engine_id: int = 1):
        import json
        key = f"scan_h2h_engine_{engine_id}"
        self.set(key, json.dumps(data))
        if engine_id == 1:
            self.set("scan_h2h", json.dumps(data))

    # ---- engine runtime status tracking --------------------------------
    def engine_status(self, engine_id: int = 1) -> dict:
        import json
        v = self.get(f"engine_status_{engine_id}")
        d = json.loads(v) if v else {}
        d.setdefault("state", "idle")
        d.setdefault("detail", "")
        d.setdefault("ts", 0)
        return d

    def set_engine_status(self, engine_id: int, state: str, detail: str = ""):
        import json, time
        payload = {"state": state, "detail": detail, "ts": int(time.time())}
        self.set(f"engine_status_{engine_id}", json.dumps(payload))

    # ---- addresses a phone could not reach ------------------------------
    # An operator that cuts the TLS handshake to an address leaves it looking
    # perfect from the relay's fixed line, so without a memory of what the
    # handsets found unusable the same address is picked again on the next
    # cycle, and the next. The memory is deliberately short. The filtering
    # moves through the day: the same handset on the same operator found one
    # address in fifty usable at midday and twenty-six in fifty that evening.
    # Remembering a refusal for half a day would rule out most of the space on
    # the strength of one bad hour.
    def mark_blocked(self, ips, ttl_hours=3):
        import json, time
        now = int(time.time())
        d = self.blocked_ips(raw=True)
        for ip in ips:
            d[ip] = now
        cutoff = now - ttl_hours * 3600
        d = {ip: ts for ip, ts in d.items() if ts >= cutoff}
        self.set("blocked_ips", json.dumps(d))

    def blocked_ips(self, raw=False, ttl_hours=3):
        import json, time
        v = self.get("blocked_ips")
        d = json.loads(v) if v else {}
        if raw:
            return d
        cutoff = time.time() - ttl_hours * 3600
        return {ip for ip, ts in d.items() if ts >= cutoff}

    def probe_token(self) -> str:
        """Shared secret the phones authenticate with; created on first use."""
        t = self.get("probe_token")
        if not t:
            import secrets
            t = secrets.token_urlsafe(24)
            self.set("probe_token", t)
        return t

    def save_device_report(self, device: str, operator: str, results: list,
                           net: str = "", app: str = "", keep_devices=12,
                           engine_id: int = 1):
        """`net` is what the phone was actually on when it measured. A round
        taken over Wi-Fi still carries the SIM's operator name, so without this
        it would pass as a measurement of that operator's route."""
        import json, time
        # Per-engine report storage
        key = f"device_reports_engine_{engine_id}"
        eng_r = self.device_reports(engine_id=engine_id)
        eng_r[device] = {"operator": operator, "ts": int(time.time()),
                         "net": net, "app": app, "results": results,
                         "engine_id": engine_id}
        if len(eng_r) > keep_devices:
            for k in sorted(eng_r, key=lambda k: eng_r[k]["ts"])[:-keep_devices]:
                eng_r.pop(k, None)
        self.set(key, json.dumps(eng_r))

        # Also update global device_reports for general heartbeat and backward compatibility
        all_r = self.device_reports(engine_id=None)
        all_r[device] = {"operator": operator, "ts": int(time.time()),
                         "net": net, "app": app, "results": results,
                         "engine_id": engine_id}
        if len(all_r) > keep_devices:
            for k in sorted(all_r, key=lambda k: all_r[k]["ts"])[:-keep_devices]:
                all_r.pop(k, None)
        self.set("device_reports", json.dumps(all_r))

    def touch_device(self, device: str, operator: str = "", net: str = "",
                     app: str = ""):
        """Record that a phone was heard from just now."""
        import json, time
        seen = self.devices_seen()
        prev = seen.get(device, {})
        seen[device] = {"ts": int(time.time()),
                        "operator": operator or prev.get("operator", ""),
                        "net": net or prev.get("net", ""),
                        "app": app or prev.get("app", "")}
        self.set("devices_seen", json.dumps(seen))

    def devices_seen(self) -> dict:
        import json
        v = self.get("devices_seen")
        return json.loads(v) if v else {}

    def forget_device(self, device: str):
        import json
        for key in ("devices_seen", "device_reports"):
            d = json.loads(self.get(key) or "{}")
            d.pop(device, None)
            self.set(key, json.dumps(d))

    def set_device_name(self, device: str, name: str):
        """A name the owner chose. The operator is what the phone reports; this
        is which physical handset it is, which only a person can know."""
        import json
        names = self.device_names()
        if name:
            names[device] = name[:32]
        else:
            names.pop(device, None)
        self.set("device_names", json.dumps(names))

    def device_names(self) -> dict:
        import json
        v = self.get("device_names")
        return json.loads(v) if v else {}

    def probe_interval(self) -> int:
        """Hours between phone measurement rounds. The phones read this."""
        try:
            return max(1, int(self.get("probe_interval", "12")))
        except (TypeError, ValueError):
            return 12

    def set_probe_interval(self, hours: int):
        self.set("probe_interval", max(1, int(hours)))

    def device_reports(self, engine_id: int | None = None) -> dict:
        import json
        if engine_id is not None:
            key = f"device_reports_engine_{engine_id}"
            v = self.get(key)
            if v:
                return json.loads(v)
            # Fallback to filtering global reports by matching candidate IPs
            cand = self.scan_candidates(engine_id=engine_id)
            cand_ips = set(cand.get("ips") or [])
            global_r = json.loads(self.get("device_reports") or "{}")
            out = {}
            for d, rep in global_r.items():
                rep_ips = {r.get("ip") for r in (rep.get("results") or []) if isinstance(r, dict)}
                if rep_ips & cand_ips or rep.get("engine_id") == engine_id:
                    out[d] = rep
            return out
        v = self.get("device_reports")
        return json.loads(v) if v else {}

    # ---- settings ------------------------------------------------------
    def get(self, k, default=None):
        r = self.con.execute("SELECT v FROM settings WHERE k = ?", (k,)).fetchone()
        return r["v"] if r else default

    def set(self, k, v):
        self.con.execute("INSERT OR REPLACE INTO settings (k, v) VALUES (?,?)", (k, str(v)))
        self.con.commit()
