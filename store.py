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

        Storing the metrics beside the addresses is what lets the phone verdicts
        be ranked across the whole shortlist later, instead of across the short
        history of addresses that happened to be applied. Plain IP strings are
        still accepted, for callers that have nothing more to say.
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
            # Reference addresses, handed to the phones mixed in with the real
            # candidates but never judged as candidates themselves.
            "controls": [c for c in (controls or []) if c]
        }
        key = f"scan_candidates_engine_{engine_id}"
        self.set(key, json.dumps(payload))
        self.set("scan_candidates", json.dumps(payload))
        if engine_id == 1:
            self.set("scan_candidates_engine_1", json.dumps(payload))

    def set_candidate_meta(self, engine_id: int = 1, **fields):
        """Bookkeeping that rides with the shortlist: what has been tried this
        window, and how many replacement lists have gone out."""
        import json
        engine_id = fields.pop("engine_id", engine_id)
        key = f"scan_candidates_engine_{engine_id}"
        v = self.get(key)
        if not v and engine_id == 1:
            v = self.get("scan_candidates")
        d = json.loads(v) if v else {}
        d.update(fields)
        self.set(key, json.dumps(d))
        self.set("scan_candidates", json.dumps(d))

    def scan_candidates(self, engine_id=None) -> dict:
        import json
        if engine_id is not None:
            key = f"scan_candidates_engine_{engine_id}"
            v = self.get(key)
            if not v and engine_id == 1:
                v = self.get("scan_candidates")
        else:
            v = self.get("scan_candidates")
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
                           net: str = "", app: str = "", keep_devices=12):
        """`net` is what the phone was actually on when it measured. A round
        taken over Wi-Fi still carries the SIM's operator name, so without this
        it would pass as a measurement of that operator's route."""
        import json, time
        all_r = self.device_reports()
        all_r[device] = {"operator": operator, "ts": int(time.time()),
                         "net": net, "app": app, "results": results}
        # Keep the newest devices only, so a lost phone cannot grow this for ever.
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

    def device_reports(self) -> dict:
        import json
        v = self.get("device_reports")
        return json.loads(v) if v else {}

    # ---- settings ------------------------------------------------------
    def get(self, k, default=None):
        r = self.con.execute("SELECT v FROM settings WHERE k = ?", (k,)).fetchone()
        return r["v"] if r else default

    def set(self, k, v):
        self.con.execute("INSERT OR REPLACE INTO settings (k, v) VALUES (?,?)", (k, str(v)))
        self.con.commit()
