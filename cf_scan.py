"""
Find the Cloudflare edge addresses that behave best from inside Iran.

Every measurement is taken from the machine this runs on, because that is the
only thing that means anything: an edge address that answers in 8 ms from
Frankfurt can be unusable from Tehran, and the whole point is to learn which
ones the domestic path actually treats well.

The scan narrows in stages, because the address space is far too large to test
properly end to end. Roughly 1.5 million addresses are announced, so the early
stages have to be cheap enough to run across all of them and the expensive
stages only ever see the handful that survived:

  1. reachable   A TCP connection to 443. One packet round trip, run massively
                 in parallel. Most candidates die here.
  2. real edge   A TLS handshake and one HTTP request, checking the response
                 actually came from Cloudflare. This removes addresses that
                 accept connections but are not serving - including anything
                 that has been transparently intercepted.
  3. stable      Repeated probes for jitter and loss. This is the stage that
                 matters most here: a domestic path will often show a fine
                 average while dropping one packet in twenty, and an average
                 alone would rank that address as excellent.
  4. fast        A real download, only for the finalists, since this is the
                 one stage that costs meaningful bandwidth.

Scoring deliberately punishes loss and jitter harder than latency. For the
traffic these addresses carry, a steady 90 ms is worth more than a 40 ms path
that stalls, and an average latency figure hides exactly that difference.
"""
import argparse
import asyncio
import ipaddress
import json
import math
import os
import random
import signal
import ssl
import statistics
import sys
import time
import urllib.request

CF_V4_URL = "https://www.cloudflare.com/ips-v4"
# Used when the list cannot be fetched - a scan from inside Iran may not be
# able to reach cloudflare.com itself.
CF_V4_FALLBACK = """173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22"""

TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE
TLS_CTX.set_alpn_protocols(["http/1.1"])


# --------------------------------------------------------------------------
# candidate generation
# --------------------------------------------------------------------------
def cloudflare_ranges():
    try:
        with urllib.request.urlopen(CF_V4_URL, timeout=20) as r:
            body = r.read().decode()
        if "/" in body:
            return [l.strip() for l in body.splitlines() if l.strip()]
    except Exception as e:
        print(f"  (could not fetch the live range list: {e}; using the built-in one)",
              file=sys.stderr)
    return [l.strip() for l in CF_V4_FALLBACK.splitlines() if l.strip()]


def candidates(ranges, per_24, seed=None):
    """
    Sample addresses spread across every /24 rather than taken at random.

    Cloudflare assigns whole /24s to a site, so addresses inside one behave
    alike while neighbouring blocks can route through entirely different
    cities. Random sampling across the whole space would test one block
    repeatedly and miss others completely.
    """
    rng = random.Random(seed)
    out = []
    for cidr in ranges:
        net = ipaddress.ip_network(cidr)
        if net.version != 4:
            continue
        for sub in net.subnets(new_prefix=24) if net.prefixlen < 24 else [net]:
            hosts = list(sub.hosts())
            if not hosts:
                continue
            out.extend(str(ip) for ip in rng.sample(hosts, min(per_24, len(hosts))))
    rng.shuffle(out)
    return out


# --------------------------------------------------------------------------
# stage 1: is anything listening
# --------------------------------------------------------------------------
async def tcp_probe(ip, port, timeout):
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        ms = (time.perf_counter() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ms
    except Exception:
        return None


def _ip_of(e):
    """The address inside a stage result, which is a tuple early and a dict later."""
    if isinstance(e, tuple):
        return e[0]
    return e["ip"] if isinstance(e, dict) else e


def _pin(subset, full, pinned):
    """
    Put the pinned addresses back into a shortened list, if they got this far.

    Every stage keeps only its best N, which is right for a random sample but
    wrong for an address the phones already vouched for: it would be cut on the
    relay's numbers alone and never reach the results, so the handsets' verdict
    on it could never be acted on.
    """
    if not pinned:
        return subset
    have = {_ip_of(e) for e in subset}
    return list(subset) + [e for e in full
                           if _ip_of(e) in pinned and _ip_of(e) not in have]


async def stage_reachable(ips, port, timeout, concurrency, progress_every=20000):
    sem = asyncio.Semaphore(concurrency)
    alive = []
    done = 0

    async def one(ip):
        nonlocal done
        async with sem:
            ms = await tcp_probe(ip, port, timeout)
        done += 1
        if done % progress_every == 0:
            print(f"    {done}/{len(ips)} probed, {len(alive)} answering", flush=True)
        if ms is not None:
            alive.append((ip, ms))

    await asyncio.gather(*(one(ip) for ip in ips))
    alive.sort(key=lambda x: x[1])
    return alive


# --------------------------------------------------------------------------
# stage 2: is it really a Cloudflare edge that will serve traffic
# --------------------------------------------------------------------------
async def http_probe(ip, host, port, path, timeout, read_bytes=0, want_body=False, sni=None):
    """One HTTPS request to a named host/SNI, forced to a specific address."""
    start = time.perf_counter()
    server_name = (sni or host).strip()
    try:
        fut = asyncio.open_connection(ip, port, ssl=TLS_CTX, server_hostname=server_name)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        tls_ms = (time.perf_counter() - start) * 1000

        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()

        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        ttfb_ms = (time.perf_counter() - start) * 1000
        headers = head.decode("latin1", "replace").lower()

        got = 0
        dl_ms = None
        body = ""
        if read_bytes:
            dl_start = time.perf_counter()
            while got < read_bytes:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                got += len(chunk)
            dl_ms = (time.perf_counter() - dl_start) * 1000
        elif want_body:
            raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            body = raw.decode("latin1", "replace")

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        status = head.split(b" ")[1].decode() if b" " in head else "?"
        body_lower = body.lower()

        # Reject known Cloudflare edge and origin errors
        cf_error = False
        cf_err_code = None
        cf_codes = ["1034", "1000", "1001", "1002", "520", "521", "522", "523", "524", "525", "526"]
        for code in cf_codes:
            if f"error code: {code}" in body_lower or f"errorcode: {code}" in body_lower or f"error {code}" in body_lower:
                cf_error = True
                cf_err_code = code
                break
        if not cf_error and status == "403" and ("cloudflare" in headers or "cf-ray" in headers) and "error" in body_lower:
            cf_error = True
            cf_err_code = "403"

        is_trace = "/cdn-cgi/trace" in path
        valid = False
        if not cf_error:
            if is_trace:
                valid = ("ip=" in body and "colo=" in body) or ("server: cloudflare" in headers and status == "200")
            elif status in ("200", "101"):
                valid = True
            elif status == "400" and ("sec-websocket-version" in headers or "bad request" in body_lower):
                valid = True
            elif status in ("204", "301", "302", "404") and not cf_error:
                valid = True

        return {"tls_ms": tls_ms, "ttfb_ms": ttfb_ms, "status": status,
                "cloudflare": ("server: cloudflare" in headers or "cf-ray" in headers),
                "valid": valid, "cf_error": cf_error, "cf_err_code": cf_err_code,
                "bytes": got, "dl_ms": dl_ms, "body": body}
    except Exception as e:
        return {"error": type(e).__name__, "valid": False, "cf_error": False}


def parse_trace(body):
    """
    Pull the fields Cloudflare reports back about the connection itself.

    The client address is stored under its own name: the row already has an
    `ip`, which is the edge being tested, and these two must never be confused.
    """
    out = {}
    for line in body.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if k == "ip":
            out["ip_trace"] = v
        elif k in ("colo", "loc", "warp"):
            out[k] = v
    return out


async def stage_edge(alive, host, port, path, timeout, concurrency, sni=None):
    """
    Keep only addresses that give a direct, unmediated, non-error path to Cloudflare.
    """
    sem = asyncio.Semaphore(concurrency)
    seen = []

    async def one(ip, tcp_ms):
        async with sem:
            r = await http_probe(ip, host, port, path, timeout, want_body=True, sni=sni)
        if "error" not in r and r.get("valid") and not r.get("cf_error"):
            seen.append({"ip": ip, "tcp_ms": tcp_ms, **r,
                         **parse_trace(r.get("body", ""))})

    await asyncio.gather(*(one(ip, ms) for ip, ms in alive))

    reported = [d["ip_trace"] for d in seen if d.get("ip_trace")]
    my_ip = max(set(reported), key=reported.count) if reported else None

    good, mediated = [], []
    for d in seen:
        if my_ip and d.get("ip_trace") and d["ip_trace"] != my_ip:
            mediated.append(d)
        else:
            good.append(d)
    good.sort(key=lambda d: d["ttfb_ms"])
    return good, mediated, my_ip


# --------------------------------------------------------------------------
# stage 3: does it stay good
# --------------------------------------------------------------------------
async def stage_stable(rows, port, timeout, rounds, concurrency):
    sem = asyncio.Semaphore(concurrency)

    async def one(row):
        async with sem:
            samples = []
            for _ in range(rounds):
                ms = await tcp_probe(row["ip"], port, timeout)
                samples.append(ms)
                await asyncio.sleep(0.12)
        ok = [s for s in samples if s is not None]
        row["loss"] = (len(samples) - len(ok)) / len(samples)
        if ok:
            row["rtt"] = statistics.median(ok)
            # Mean absolute deviation rather than stdev: a single stalled probe
            # should register, not be squared into dominating the figure.
            row["jitter"] = statistics.mean(abs(x - row["rtt"]) for x in ok)
            row["rtt_max"] = max(ok)
        else:
            row["rtt"] = row["jitter"] = row["rtt_max"] = None
        return row

    return await asyncio.gather(*(one(r) for r in rows))


# --------------------------------------------------------------------------
# stage 4: throughput, for the finalists only
# --------------------------------------------------------------------------
async def stage_speed(rows, host, port, size_bytes, timeout, concurrency):
    # Deliberately low concurrency: parallel downloads compete for the same
    # uplink and would measure the server's own limit rather than each edge.
    sem = asyncio.Semaphore(concurrency)
    path = f"/__down?bytes={size_bytes}"

    async def one(row):
        async with sem:
            r = await http_probe(row["ip"], host, port, path, timeout,
                                 read_bytes=size_bytes)
        if "error" in r or not r.get("dl_ms"):
            row["mbps"] = 0.0
        else:
            row["mbps"] = (r["bytes"] * 8) / (r["dl_ms"] / 1000) / 1e6
        return row

    return await asyncio.gather(*(one(r) for r in rows))


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------
def score(row):
    """
    Lower is better. Loss dominates, jitter counts double against latency.

    A path that drops one probe in twenty is unusable for a tunnel even at
    30 ms, so loss is weighted far above anything else; ranking on the average
    alone would put exactly that address at the top.
    """
    if not row.get("rtt") or not math.isfinite(row["rtt"]):
        return float("inf")
    cost = row["rtt"] + 2.0 * row["jitter"] + 1000.0 * row["loss"]
    if row.get("mbps"):
        # A fast edge earns a discount, capped so throughput cannot outweigh
        # a path that is unstable.
        cost -= min(row["mbps"], 100.0) * 0.5
    return cost


_write_lock = False


def write_results(rows: list[dict], out_base: str, scan_start: float | None = None, engine_id: int = 0):
    """
    Write ranked candidates to out_base.json and out_base.txt atomically.
    Guarded against signal handler re-entrancy.
    """
    global _write_lock
    if _write_lock:
        return
    _write_lock = True
    try:
        if not rows:
            return
        valid_rows = [
            r for r in rows
            if isinstance(r, dict) and r.get("ip") and r.get("rtt") is not None and math.isfinite(r["rtt"])
        ]
        if not valid_rows:
            return

        payload = {
            "scan_start": int(scan_start) if scan_start is not None else int(time.time()),
            "engine_id": int(engine_id),
            "results": valid_rows,
        }

        tmp_json = f"{out_base}.json.tmp"
        with open(tmp_json, "w") as f:
            json.dump(payload, f, indent=1, allow_nan=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_json, f"{out_base}.json")

        tmp_txt = f"{out_base}.txt.tmp"
        with open(tmp_txt, "w") as f:
            f.write("\n".join(r["ip"] for r in valid_rows if r.get("loss") == 0) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_txt, f"{out_base}.txt")
    finally:
        _write_lock = False


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="speed.cloudflare.com",
                    help="hostname to request; use your own Cloudflare domain "
                         "to measure exactly what your users get")
    ap.add_argument("--sni", default="",
                    help="TLS SNI server name to send; defaults to --host if empty")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--path", default="/cdn-cgi/trace")
    ap.add_argument("--per-24", type=int, default=1, help="addresses sampled per /24")
    ap.add_argument("--limit", type=int, default=0, help="cap candidates (0 = all)")
    ap.add_argument("--connect-timeout", type=float, default=2.0)
    ap.add_argument("--http-timeout", type=float, default=6.0)
    ap.add_argument("--concurrency", type=int, default=400)
    ap.add_argument("--edge-keep", type=int, default=120, help="carried into the stability stage")
    ap.add_argument("--final", type=int, default=20, help="carried into the speed stage")
    ap.add_argument("--rounds", type=int, default=12, help="probes per address for jitter")
    ap.add_argument("--speed-bytes", type=int, default=2_000_000)
    ap.add_argument("--no-speed", action="store_true", help="skip the download stage")
    ap.add_argument("--out", default="/root/cf_results")
    ap.add_argument("--engine-id", type=int, default=0, help="scanner engine ID")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--only", default="",
                    help="measure exactly these addresses and sample nothing; "
                         "used to re-check a shortlist properly at the end of a "
                         "window instead of scanning the space again")
    ap.add_argument("--include", default="",
                    help="comma-separated addresses to measure whatever the "
                         "random sample turned up, and to carry through every "
                         "stage (used for addresses the phones vouched for)")
    args = ap.parse_args()

    t0 = time.time()
    current_candidates: list[dict] = []
    current_out: str = args.out

    def sigterm_handler(signum, frame):
        if current_candidates:
            print("\n  SIGTERM received; saving partial results...", file=sys.stderr, flush=True)
            write_results(current_candidates, current_out, scan_start=t0, engine_id=args.engine_id)
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, sigterm_handler)

    only = [x.strip() for x in args.only.split(",") if x.strip()]
    if only:
        ranges, ips = [], only
        print(f"  measuring a fixed list of {len(ips)} address(es)", flush=True)
    else:
        ranges = cloudflare_ranges()
        ips = candidates(ranges, args.per_24, args.seed)
        if args.limit:
            ips = ips[:args.limit]
    pinned = {ip.strip() for ip in args.include.split(",") if ip.strip()}
    if pinned:
        ips = list(pinned) + [i for i in ips if i not in pinned]
        print(f"  pinned: {len(pinned)} address(es) carried through every stage",
              flush=True)
    if not only:
        print(f"  ranges: {len(ranges)}   candidates: {len(ips)}", flush=True)

    print("  stage 1  reachable", flush=True)
    alive = await stage_reachable(ips, args.port, args.connect_timeout, args.concurrency)
    print(f"    {len(alive)} answered on {args.port}", flush=True)
    if not alive:
        print("  nothing answered - this path may block Cloudflare entirely.")
        return

    current_candidates = [{"ip": r["ip"], "rtt": r["rtt"], "jitter": 0.0, "loss": 0.0} for r in alive]

    keep = alive if only else _pin(alive[:max(args.edge_keep * 4, 400)], alive, pinned)
    print(f"  stage 2  confirming Cloudflare on the {len(keep)} quickest", flush=True)
    good, mediated, my_ip = await stage_edge(
        keep, args.host, args.port, args.path,
        args.http_timeout, min(args.concurrency, 100), sni=args.sni or None)
    print(f"    this machine appears to Cloudflare as {my_ip}", flush=True)
    print(f"    {len(good)} direct, {len(mediated)} reached through something else",
          flush=True)
    if mediated:
        for d in mediated[:5]:
            print(f"      excluded {d['ip']:<16} seen as {d.get('ip_trace')} "
                  f"via {d.get('colo', '?')}/{d.get('loc', '?')}", flush=True)
    if not good:
        print("  none served a Cloudflare response - the TLS path is likely interfered with.")
        return

    current_candidates = list(good)

    finalists = good if only else _pin(good[:args.edge_keep], good, pinned)
    print(f"  stage 3  stability over {args.rounds} probes each", flush=True)
    finalists = await stage_stable(finalists, args.port, args.connect_timeout,
                                   args.rounds, min(args.concurrency, 60))
    finalists.sort(key=score)
    current_candidates = list(finalists)

    # Stage 3 checkpoint: write partial results immediately before stage 4 starts
    write_results(finalists, args.out, scan_start=t0, engine_id=args.engine_id)

    if not args.no_speed:
        top = finalists if only else _pin(finalists[:args.final], finalists, pinned)
        mb = args.speed_bytes / 1e6
        print(f"  stage 4  download {mb:.1f} MB from the best {len(top)}"
              f"  (~{mb * len(top):.0f} MB total)", flush=True)
        top = await stage_speed(top, "speed.cloudflare.com", args.port,
                                args.speed_bytes, max(args.http_timeout, 25), 3)
        done = {r["ip"] for r in top}
        finalists = top + [r for r in finalists if r["ip"] not in done]
        finalists.sort(key=score)
        current_candidates = list(finalists)

    print()
    print(f"  {'#':<4}{'address':<17}{'rtt':>8}{'jitter':>9}{'loss':>7}"
          f"{'worst':>9}{'speed':>11}   colo")
    for i, r in enumerate(finalists[:args.final], 1):
        speed = f"{r['mbps']:.1f} Mbps" if r.get("mbps") else "-"
        rtt_s = f"{r['rtt']:>7.1f}ms" if (r.get("rtt") is not None and math.isfinite(r["rtt"])) else f"{'-':>9}"
        jit_s = f"{r['jitter']:>8.1f}ms" if (r.get("jitter") is not None and math.isfinite(r["jitter"])) else f"{'-':>10}"
        loss_s = f"{r['loss'] * 100:>6.0f}%" if (r.get("loss") is not None and math.isfinite(r["loss"])) else f"{'-':>7}"
        max_s = f"{r['rtt_max']:>8.1f}ms" if (r.get("rtt_max") is not None and math.isfinite(r["rtt_max"])) else f"{'-':>10}"
        print(f"  {i:<4}{r['ip']:<17}{rtt_s}{jit_s}{loss_s}{max_s}{speed:>11}   "
              f"{r.get('colo', '?')}")

    write_results(finalists, args.out, scan_start=t0, engine_id=args.engine_id)
    print(f"\n  full results: {args.out}.json")
    print(f"  loss-free addresses only: {args.out}.txt")
    print(f"  took {time.time() - t0:.0f}s")


if __name__ == "__main__":
    asyncio.run(main())
