#!/usr/bin/env python3
"""
Probe VPN endpoints from inside Iran and report how healthy each one really is.

A config does not usually die by going unreachable - it dies by being filtered,
and filtering does not look like downtime. The common pattern is that TCP still
connects (the IP is routable) but the TLS handshake is reset as soon as the SNI
is seen. So every target is measured twice: a plain TCP connect, and, where the
endpoint is TLS, a real handshake with the real SNI. A target that passes TCP
and fails TLS is filtered, not down, and that distinction is the whole point.

Each check is repeated: Iranian transit is lossy enough that a single failed
connect proves nothing, and a single success does not prove a config is usable.

Reads a JSON list of targets on stdin, writes a JSON list of results on stdout.
"""
import asyncio
import json
import ssl
import sys
import time

ROUNDS = 6
TCP_TIMEOUT = 4.0
TLS_TIMEOUT = 7.0


async def _close(w):
    try:
        w.close()
        await asyncio.wait_for(w.wait_closed(), timeout=2)
    except Exception:
        pass


async def tcp_once(host, port):
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port),
                                      timeout=TCP_TIMEOUT)
        ms = (time.perf_counter() - t0) * 1000
        await _close(w)
        return True, ms, None
    except Exception as e:
        return False, None, type(e).__name__


async def tls_once(host, port, sni):
    ctx = ssl.create_default_context()
    # We are testing reachability and filtering, not certificate trust: many of
    # these endpoints legitimately present a cert for a different name.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=sni or host),
            timeout=TLS_TIMEOUT)
        ms = (time.perf_counter() - t0) * 1000
        await _close(w)
        return True, ms, None
    except Exception as e:
        return False, None, type(e).__name__


async def check(t):
    host, port = t["host"], int(t["port"])
    use_tls = bool(t.get("tls"))
    sni = t.get("sni") or host

    ok = 0
    lat = []
    errs = []
    for _ in range(ROUNDS):
        good, ms, err = await tcp_once(host, port)
        if good:
            ok += 1
            lat.append(ms)
        elif err:
            errs.append(err)
        await asyncio.sleep(0.25)

    res = {
        "id": t.get("id"),
        "label": t.get("label"),
        "host": host, "port": port, "tls": use_tls,
        "tcp_ratio": round(ok / ROUNDS, 3),
        "tcp_ms": round(sum(lat) / len(lat), 1) if lat else None,
        "tcp_ms_max": round(max(lat), 1) if lat else None,
        "error": errs[0] if errs and not lat else (errs[0] if errs else None),
    }

    # Only bother with TLS if the port answers at all; a handshake against a
    # dead port tells us nothing new.
    if use_tls and ok:
        tls_ok = 0
        tls_lat = []
        tls_err = []
        for _ in range(3):
            good, ms, err = await tls_once(host, port, sni)
            if good:
                tls_ok += 1
                tls_lat.append(ms)
            elif err:
                tls_err.append(err)
            await asyncio.sleep(0.25)
        res["tls_ratio"] = round(tls_ok / 3, 3)
        res["tls_ms"] = round(sum(tls_lat) / len(tls_lat), 1) if tls_lat else None
        if tls_err and not tls_lat:
            res["error"] = tls_err[0]
    elif use_tls:
        res["tls_ratio"] = 0.0
        res["tls_ms"] = None

    res["verdict"] = verdict(res)
    return res


def verdict(r):
    """
    healthy  - usable right now
    filtered - the port answers but TLS is being reset (classic SNI filtering)
    degraded - works, but loses enough connections that users will complain
    down     - not reachable
    """
    tcp = r["tcp_ratio"]
    if tcp < 0.2:
        return "down"
    if r["tls"]:
        tls = r.get("tls_ratio", 0)
        if tls == 0:
            return "filtered"
        if tls < 0.67 or tcp < 0.7:
            return "degraded"
        return "healthy"
    if tcp < 0.5:
        return "down"
    if tcp < 0.85:
        return "degraded"
    return "healthy"


async def main():
    targets = json.loads(sys.stdin.read())
    # Concurrent, but each target's own rounds stay sequential so one slow
    # endpoint cannot inflate another's latency.
    results = await asyncio.gather(*(check(t) for t in targets),
                                   return_exceptions=True)
    out = []
    for t, r in zip(targets, results):
        if isinstance(r, Exception):
            out.append({"id": t.get("id"), "label": t.get("label"),
                        "host": t.get("host"), "port": t.get("port"),
                        "verdict": "down", "error": type(r).__name__,
                        "tcp_ratio": 0.0})
        else:
            out.append(r)
    print(json.dumps(out))


if __name__ == "__main__":
    asyncio.run(main())
