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
    proxy_family TEXT NOT NULL DEFAULT 'default', -- default | ipv4 | ipv6
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


def _fernet():
    if not os.path.exists(KEY_PATH):
        os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_PATH, "rb") as f:
        return Fernet(f.read())


class Store:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.con = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        # Existing installations predate the per-proxy IP-family preference.
        # SQLite's CREATE TABLE IF NOT EXISTS does not add columns, so migrate
        # them in place without touching their encrypted credentials.
        columns = {r["name"] for r in self.con.execute("PRAGMA table_info(accounts)")}
        if "proxy_family" not in columns:
            self.con.execute("ALTER TABLE accounts ADD COLUMN proxy_family TEXT NOT NULL DEFAULT 'default'")
            self.con.commit()
        self.f = _fernet()

    # ---- accounts ------------------------------------------------------
    def add_account(self, label, provider, token, proxy=None, proxy_family="default"):
        self.con.execute(
            "INSERT INTO accounts (label, provider, token, proxy, proxy_family, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (label, provider, self.f.encrypt(token.encode()),
             self.f.encrypt(proxy.encode()) if proxy else None, proxy_family, int(time.time())))
        self.con.commit()
        return self.con.execute("SELECT last_insert_rowid()").fetchone()[0]

    def delete_account(self, acc_id):
        n = self.con.execute("DELETE FROM accounts WHERE id = ?", (acc_id,)).rowcount
        self.con.commit()
        return n

    def set_proxy(self, acc_id, proxy, proxy_family="default"):
        """Set, change, or clear (proxy=None) an account's proxy preference."""
        self.con.execute(
            "UPDATE accounts SET proxy = ?, proxy_family = ? WHERE id = ?",
            (self.f.encrypt(proxy.encode()) if proxy else None, proxy_family, acc_id))
        self.con.commit()

    def _row(self, r):
        return {
            "id": r["id"], "label": r["label"], "provider": r["provider"],
            "token": self.f.decrypt(r["token"]).decode(),
            "proxy": self.f.decrypt(r["proxy"]).decode() if r["proxy"] else None,
            "proxy_family": r["proxy_family"],
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
    def set_cfscan(self, cfg: dict):
        import json
        self.set("cfscan", self.f.encrypt(json.dumps(cfg).encode()).decode())

    def cfscan(self) -> dict:
        import json
        v = self.get("cfscan")
        return json.loads(self.f.decrypt(v.encode()).decode()) if v else {}

    def update_cfscan(self, **fields):
        cfg = self.cfscan()
        cfg.update(fields)
        self.set_cfscan(cfg)
        return cfg

    def add_found_ip(self, entry: dict, keep=20):
        """Record a newly chosen best IP (metrics only, no secrets)."""
        import json, time
        hist = self.found_ips()
        entry = {**entry, "ts": int(time.time())}
        hist.insert(0, entry)
        self.set("cfscan_found", json.dumps(hist[:keep]))

    def found_ips(self) -> list:
        import json
        v = self.get("cfscan_found")
        return json.loads(v) if v else []

    # ---- panel connection (encrypted: it is an admin login) ------------
    # Kept here rather than in the environment so an installation can be set up
    # entirely from Telegram. Nothing about the panel is baked into the image.
    def set_panel(self, url, user, password, core_id):
        self._set_enc("panel", {"url": url.rstrip("/"), "user": user,
                                "password": password, "core_id": int(core_id)})

    def panel(self) -> dict:
        return self._get_enc("panel") or {}

    def _set_enc(self, k, obj):
        import json
        self.set(k, self.f.encrypt(json.dumps(obj).encode()).decode())

    def _get_enc(self, k):
        import json
        v = self.get(k)
        return json.loads(self.f.decrypt(v.encode()).decode()) if v else None

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

    # ---- settings ------------------------------------------------------
    def get(self, k, default=None):
        r = self.con.execute("SELECT v FROM settings WHERE k = ?", (k,)).fetchone()
        return r["v"] if r else default

    def set(self, k, v):
        self.con.execute("INSERT OR REPLACE INTO settings (k, v) VALUES (?,?)", (k, str(v)))
        self.con.commit()
