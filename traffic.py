"""Lifetime traffic per cloud account, kept after servers / Fastly services are removed.

Providers report bytes in three shapes, folded into one table of (key, bucket) rows:
  counter  running total that can reset (Hetzner, Linode): only growth is added to today's bucket
  buckets  absolute per-day / per-month totals (Vultr, Fastly): each bucket is replaced
Every server is read once more right before it is deleted (Provider.delete_server), so its final
bytes are not lost. Stored in traffic.db next to the main database; credentials never go in it.
"""

import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

log = logging.getLogger("cloudbot.traffic")
SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic(key TEXT NOT NULL, bucket TEXT NOT NULL, acct INTEGER NOT NULL,
  label TEXT NOT NULL DEFAULT '', out INTEGER NOT NULL DEFAULT 0, in_ INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(key,bucket));
CREATE INDEX IF NOT EXISTS traffic_acct ON traffic(acct);
CREATE TABLE IF NOT EXISTS trafficlast(key TEXT PRIMARY KEY, out INTEGER NOT NULL, in_ INTEGER NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS trafficerr(acct INTEGER PRIMARY KEY, err TEXT NOT NULL, at REAL NOT NULL);
"""
SUPPORTED = ("hetzner", "linode", "vultr", "fastly")
FASTLY_ALL = "fastly:all"


def _path():
    db = os.environ.get("CLOUDBOT_DB", "/opt/cloudbot/data/cloudbot.db")
    return os.environ.get("CLOUDBOT_TRAFFIC_DB", os.path.join(os.path.dirname(db), "traffic.db"))


def _con():
    con = sqlite3.connect(_path(), timeout=10)
    con.executescript(SCHEMA)
    return con


def record(key, acct, label, counter=None, buckets=None, now=None):
    """counter = (out, in) running totals; buckets = {bucket: (out, in)} absolute values."""
    now = now or time.time()
    day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
    con = _con()
    try:
        if counter is not None:
            row = con.execute("SELECT out,in_ FROM trafficlast WHERE key=?", (key,)).fetchone()
            d = [counter[0], counter[1]] if row is None else [counter[0] - row[0], counter[1] - row[1]]
            d = [counter[i] if d[i] < 0 else d[i] for i in (0, 1)]  # drop = counter reset
            con.execute("INSERT INTO traffic(key,bucket,acct,label,out,in_) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(key,bucket) DO UPDATE SET out=out+excluded.out,in_=in_+excluded.in_,label=COALESCE(NULLIF(excluded.label,''),label)",
                        (key, day, acct, label, d[0], d[1]))
            con.execute("INSERT INTO trafficlast(key,out,in_,ts) VALUES(?,?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET out=excluded.out,in_=excluded.in_,ts=excluded.ts",
                        (key, counter[0], counter[1], now))
        for b, (o, i) in (buckets or {}).items():
            con.execute("INSERT INTO traffic(key,bucket,acct,label,out,in_) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(key,bucket) DO UPDATE SET out=MAX(out,excluded.out),in_=MAX(in_,excluded.in_),label=COALESCE(NULLIF(excluded.label,''),label)",
                        (key, b, acct, label, o, i))
        if buckets and key.startswith("fastly:"):
            # older versions stored Fastly per month; the day rows now cover those months, so drop them (no double count)
            first = min(buckets)
            con.execute("DELETE FROM traffic WHERE key=? AND length(bucket)=7 AND bucket>=?", (key, first[:7]))
        if buckets:
            con.execute("INSERT INTO trafficlast(key,out,in_,ts) VALUES(?,0,0,?) ON CONFLICT(key) DO UPDATE SET ts=excluded.ts", (key, now))
        con.commit()
    finally:
        con.close()


def totals(acct, provider=None):
    con = _con()
    try:
        where, args = "acct=?", [acct]
        if provider == "fastly" and con.execute("SELECT 1 FROM traffic WHERE acct=? AND key=?", (acct, FASTLY_ALL)).fetchone():
            where += " AND key=?"; args.append(FASTLY_ALL)  # Fastly's own account-wide figure covers every service
        o, i, n, since = con.execute(f"SELECT COALESCE(SUM(out),0),COALESCE(SUM(in_),0),COUNT(DISTINCT key),COALESCE(MIN(bucket),'') FROM traffic WHERE {where}", args).fetchone()
        synced = con.execute("SELECT COALESCE(MAX(ts),0) FROM trafficlast WHERE key IN (SELECT key FROM traffic WHERE acct=?)", (acct,)).fetchone()[0]
        err = con.execute("SELECT err FROM trafficerr WHERE acct=?", (acct,)).fetchone()
        rows = [{"key": k, "label": lb, "out": ro, "in": ri, "since": s} for k, lb, ro, ri, s in con.execute(
            "SELECT key,label,SUM(out),SUM(in_),MIN(bucket) FROM traffic WHERE acct=? GROUP BY key ORDER BY SUM(out)+SUM(in_) DESC", (acct,))]
        return {"supported": provider in SUPPORTED if provider else True, "out": o, "in": i, "total": o + i, "items": n,
                "since": since, "synced_at": synced or None, "error": err[0] if err else None, "servers": rows}
    finally:
        con.close()


def _set_err(acct, err):
    con = _con()
    try:
        if err:
            con.execute("INSERT INTO trafficerr(acct,err,at) VALUES(?,?,?) ON CONFLICT(acct) DO UPDATE SET err=excluded.err,at=excluded.at", (acct, str(err)[:300], time.time()))
        else:
            con.execute("DELETE FROM trafficerr WHERE acct=?", (acct,))
        con.commit()
    finally:
        con.close()


async def read_server(provider, server_id):
    """(counter, buckets) for one server, or None when the provider has no traffic source."""
    p = provider.provider
    if p == "hetzner":
        d = await provider._req("GET", f"/servers/{server_id}")
        s = d.get("server", d)
        return (int(s.get("outgoing_traffic") or 0), int(s.get("ingoing_traffic") or 0)), None
    if p == "linode":  # bytes used this month (the instance endpoint is bytes, unlike the account one), in + out together
        d = await provider._req("GET", f"/linode/instances/{server_id}/transfer")
        return (int(float(d.get("used") or 0)), 0), None
    if p == "vultr":
        d = await provider._req("GET", f"/instances/{server_id}/bandwidth")
        days = d.get("bandwidth", {})
        return None, {day: (int(v.get("outgoing_bytes") or 0), int(v.get("incoming_bytes") or 0)) for day, v in days.items()}
    return None


FASTLY_DAY = 86400


async def read_fastly(provider, service=None):
    """{day: (bytes, 0)} for an account or one service.

    Fastly rolls its day / month figures up with a lag of about a day, so `by=month` alone freezes for a day
    and then jumps, and misses everything since the last rollup. Finished days come from `by=day`; the days
    after the last rollup are summed from the live `by=hour` rows."""
    base = f"/stats/service/{service}" if service else "/stats/aggregate"
    now = int(time.time())
    day = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
    d = await provider._req("GET", f"{base}?from={now - 800 * FASTLY_DAY}&to={now}&by=day")
    out, rolled = {}, 0
    for row in d.get("data", []):
        st = int(row.get("start_time") or 0)
        b = day(st)
        out[b] = (out.get(b, (0, 0))[0] + int(row.get("bandwidth") or 0), 0)
        rolled = max(rolled, st + FASTLY_DAY)
    frm = rolled or now - 14 * FASTLY_DAY
    h = await provider._req("GET", f"{base}?from={frm}&to={now}&by=hour")
    tail = {}
    for row in h.get("data", []):
        st = int(row.get("start_time") or 0)
        if st >= frm:
            b = day(st)
            tail[b] = tail.get(b, 0) + int(row.get("bandwidth") or 0)
    for b, v in tail.items():
        out[b] = (max(v, out.get(b, (0, 0))[0]), 0)
    return out


async def sample_server(provider, server):
    got = await read_server(provider, server["id"])
    if got:
        record(f"{provider.provider}:{server['id']}", provider.account["id"], server.get("label") or "", counter=got[0], buckets=got[1])


async def sample_account(provider, servers=None):
    """Read every server (or Fastly account) once; the error, if any, is kept for the UI."""
    acct = provider.account["id"]
    if provider.provider not in SUPPORTED:
        return
    first = None
    try:
        if provider.provider == "fastly":
            record(FASTLY_ALL, acct, "all services on the account", buckets=await read_fastly(provider))
            for s in await provider.fastly_services():
                try:
                    record(f"fastly:{s['id']}", acct, s.get("name") or s["id"], buckets=await read_fastly(provider, s["id"]))
                except Exception as e:
                    first = first or e
        else:
            for s in servers if servers is not None else await provider.list_servers():
                try:
                    await sample_server(provider, s)
                except Exception as e:
                    first = first or e
    except Exception as e:
        first = first or e
    _set_err(acct, first)


async def sample_before_delete(provider, server_id):
    """Final reading of a server about to be deleted. Never blocks or fails the delete."""
    if provider.provider not in SUPPORTED or provider.provider == "fastly":
        return
    try:
        await sample_server(provider, {"id": server_id})
    except Exception:
        log.warning("final traffic read of %s failed", server_id, exc_info=True)
