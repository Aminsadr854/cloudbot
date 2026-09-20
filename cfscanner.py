"""
Run the Cloudflare clean-IP scan from inside Iran.

The scan MUST run from the vantage point the customers actually use - a clean
edge measured from Frankfurt means nothing in Tehran - so the bot ships the
scanner to an Iran server over SSH and runs it there, then reads the ranked
result back. The scanner itself (cf_scan.py) narrows ~1.5M announced addresses
in stages: TCP-reachable, then a real Cloudflare TLS/HTTP handshake with an
interception check, then repeated probes for loss and jitter, then a real
download on the finalists. Ranking punishes loss and jitter far above latency,
because a steady 90 ms path beats a 40 ms one that stalls.
"""
import asyncio
import json
import logging
import math
import os
import shlex
import time

import tunnel  # reuse the SSH connector (direct, or via the Iran jump)

logger = logging.getLogger("cfscanner")

SCANNER_LOCAL = os.path.join(os.path.dirname(__file__), "cf_scan.py")
REMOTE_OUT = "/root/cf_bot_scan"

REMOTE_TIMEOUT = 900
LOCAL_TIMEOUT = 960

DEFAULT_CONCURRENCY = 200
MAX_CONCURRENT_SCANS = 1
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


class ScanTimeoutError(TimeoutError):
    pass


class StaleResultError(RuntimeError):
    pass


import urllib.request

RANGES_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".cf_ranges_cache.txt")
RANGES_CACHE_TTL = 6 * 3600  # at least 6 hours
CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"

_in_memory_ranges: str | None = None
_in_memory_ranges_ts: float = 0.0
_cache_write_warned: bool = False


def _get_cached_ranges() -> str:
    """
    Fetch Cloudflare range list on the bot host, caching it for at least 6 hours.
    Falls back to CF_V4_FALLBACK if fetch fails and cache is absent.
    """
    global _in_memory_ranges, _in_memory_ranges_ts, _cache_write_warned
    now = time.time()

    # 1. If valid disk cache exists, use it
    if os.path.exists(RANGES_CACHE_FILE):
        try:
            mtime = os.path.getmtime(RANGES_CACHE_FILE)
            if now - mtime < RANGES_CACHE_TTL:
                with open(RANGES_CACHE_FILE) as f:
                    content = f.read().strip()
                if content and "/" in content:
                    _in_memory_ranges = content
                    _in_memory_ranges_ts = mtime
                    return content
        except Exception:
            pass

    # 2. If valid in-memory cache exists (e.g. unwritable disk directory), use it
    if _in_memory_ranges and (now - _in_memory_ranges_ts < RANGES_CACHE_TTL):
        return _in_memory_ranges

    # 3. Fetch live on bot host
    try:
        with urllib.request.urlopen(CF_RANGES_URL, timeout=20) as r:
            body = r.read().decode().strip()
        if "/" in body:
            _in_memory_ranges = body
            _in_memory_ranges_ts = now
            try:
                tmp_cache = f"{RANGES_CACHE_FILE}.tmp.{os.getpid()}"
                with open(tmp_cache, "w") as f:
                    f.write(body + "\n")
                os.replace(tmp_cache, RANGES_CACHE_FILE)
            except Exception as e:
                if not _cache_write_warned:
                    logger.warning("Could not write Cloudflare ranges cache to %s: %s", RANGES_CACHE_FILE, e)
                    _cache_write_warned = True
            return body
    except Exception:
        pass

    # 4. If live fetch failed but in-memory cache exists, use it
    if _in_memory_ranges:
        return _in_memory_ranges

    # 5. If live fetch failed but stale disk cache exists, use it
    if os.path.exists(RANGES_CACHE_FILE):
        try:
            with open(RANGES_CACHE_FILE) as f:
                content = f.read().strip()
            if content and "/" in content:
                _in_memory_ranges = content
                _in_memory_ranges_ts = os.path.getmtime(RANGES_CACHE_FILE)
                return content
        except Exception:
            pass

    from cf_scan import CF_V4_FALLBACK
    return CF_V4_FALLBACK.strip()



EXCLUDE_FILE_THRESHOLD = 250  # IPs (~4KB); above this threshold, ship as a file to avoid ARG_MAX


def _load_scanner() -> str:
    with open(SCANNER_LOCAL) as f:
        return f.read()


def _build_scan_args(remote_scanner: str, out_file: str, *, per_24=2, rounds=14,
                     final=20, host="speed.cloudflare.com", sni: str | None = None,
                     limit=0, only=None, no_speed=False, include=None, engine_id: int = 0,
                     concurrency: int = DEFAULT_CONCURRENCY,
                     ranges_file: str | None = None,
                     exclude=None, exclude_file: str | None = None) -> list[str]:
    args = ["python3", remote_scanner,
            "--per-24", str(per_24),
            "--rounds", str(rounds),
            "--final", str(final),
            "--host", host,
            "--concurrency", str(concurrency),
            "--out", out_file]
    if engine_id:
        args += ["--engine-id", str(engine_id)]
    if sni:
        args += ["--sni", sni]
    if limit:
        args += ["--limit", str(int(limit))]
    if ranges_file:
        args += ["--ranges-file", ranges_file]
    if exclude_file:
        args += ["--exclude-file", exclude_file]
    if exclude:
        safe_exc = [i for i in exclude if all(ch in "0123456789." for ch in i)]
        if safe_exc:
            args += ["--exclude", ",".join(safe_exc)]
    if only:
        safe_only = [i for i in only if all(ch in "0123456789." for ch in i)]
        if safe_only:
            args += ["--only", ",".join(safe_only)]
    if no_speed:
        args.append("--no-speed")
    if include:
        safe_inc = [i for i in include if all(ch in "0123456789." for ch in i)]
        if safe_inc:
            args += ["--include", ",".join(safe_inc)]
    return args


async def run_scan(ssh: dict, jump: dict | None, log, *, per_24=2, rounds=14,
                   final=20, host="speed.cloudflare.com", sni: str | None = None,
                   include=None, limit=0, only=None, no_speed=False, engine_id: int = 1,
                   remote_out: str | None = None, concurrency: int = DEFAULT_CONCURRENCY,
                   exclude=None):
    """
    SSH to `ssh` (optionally via `jump`), run the scanner, return the ranked
    result list (best first). Each item: ip, rtt, jitter, loss, rtt_max, mbps.
    `log` is an async callable for progress.
    `engine_id` isolates output files on the remote server when multiple engines scan.
    `sni` allows probing with the actual domain SNI.
    """
    remote_script = f"/root/.cf_scan_engine_{engine_id}.py"
    tmp_path = f"{remote_script}.tmp.{os.getpid()}"
    remote_ranges_file = f"/root/.cf_ranges_engine_{engine_id}.txt"
    tmp_ranges_path = f"{remote_ranges_file}.tmp.{os.getpid()}"
    out_file = remote_out or (f"/root/cf_bot_scan_engine_{engine_id}" if engine_id else REMOTE_OUT)

    safe_exclude = [i for i in (exclude or []) if all(ch in "0123456789." for ch in i)]
    remote_exclude_file = None
    tmp_exclude_path = None
    exclude_inline = None
    if len(safe_exclude) > EXCLUDE_FILE_THRESHOLD:
        remote_exclude_file = f"/root/.cf_exclude_engine_{engine_id}.txt"
        tmp_exclude_path = f"{remote_exclude_file}.tmp.{os.getpid()}"
    elif safe_exclude:
        exclude_inline = safe_exclude

    # Lock ordering and deadlock prevention:
    # In ScannerEngine.scan_loop, each engine first acquires its per-engine lock (`self.lock`).
    # Then it calls run_scan(), which acquires the global SCAN_SEMAPHORE across all engines.
    # Because lock acquisition order is strictly:
    #   Level 1: Per-engine lock (ScannerEngine.lock)
    #   Level 2: Global scan semaphore (SCAN_SEMAPHORE)
    # and SCAN_SEMAPHORE is never held while waiting to acquire self.lock,
    # circular wait cannot occur and deadlock is impossible.
    async with SCAN_SEMAPHORE:
        conn = await tunnel.connect(ssh["host"], int(ssh.get("port", 22)),
                                    ssh["user"], ssh["password"], jump=jump)
        try:
            # Before starting a new scan on an engine, verify no previous cf_scan.py is
            # still running for that engine. If one is, terminate it before starting.
            check_cmd = f"pgrep -f {shlex.quote(remote_script)} 2>/dev/null"
            prev_proc = await conn.run(check_cmd, check=False)
            if prev_proc.stdout and prev_proc.stdout.strip():
                if callable(log):
                    await log(f"اسکن قبلی موتور {engine_id} در حال اجراست؛ متوقف می‌شود…")
                await conn.run(f"pkill -15 -f {shlex.quote(remote_script)} 2>/dev/null", check=False)
                await asyncio.sleep(2)
                check_still = await conn.run(check_cmd, check=False)
                if check_still.stdout and check_still.stdout.strip():
                    await conn.run(f"pkill -9 -f {shlex.quote(remote_script)} 2>/dev/null", check=False)

            # Delete previous outputs for this engine only (including .tmp siblings)
            clean_cmd = (f"rm -f {shlex.quote(out_file + '.json')} "
                         f"{shlex.quote(out_file + '.txt')} "
                         f"{shlex.quote(out_file + '.json.tmp')} "
                         f"{shlex.quote(out_file + '.txt.tmp')}")
            await conn.run(clean_cmd, check=False)

            scan_start_time = int(time.time())

            await log("در حال آماده‌سازی اسکنر روی سرور ایران…")
            script = _load_scanner()
            ranges_content = _get_cached_ranges()
            # Write scanner, cached ranges, and optional exclude file via SFTP to unique temp paths, then atomically rename
            async with conn.start_sftp_client() as sftp:
                async with sftp.open(tmp_path, "w") as f:
                    await f.write(script)
                async with sftp.open(tmp_ranges_path, "w") as f:
                    await f.write(ranges_content + "\n")
                if remote_exclude_file and tmp_exclude_path:
                    async with sftp.open(tmp_exclude_path, "w") as f:
                        await f.write("\n".join(safe_exclude) + "\n")

            rename_cmd = (f"mv {shlex.quote(tmp_path)} {shlex.quote(remote_script)} && "
                          f"mv {shlex.quote(tmp_ranges_path)} {shlex.quote(remote_ranges_file)}")
            if remote_exclude_file and tmp_exclude_path:
                rename_cmd += f" && mv {shlex.quote(tmp_exclude_path)} {shlex.quote(remote_exclude_file)}"
            await conn.run(rename_cmd, check=False)

            # Raise the fd limit inline: every probe in flight holds one, and the
            # default 1024 would silently cap concurrency and lose candidates.
            args = _build_scan_args(
                remote_script, out_file, per_24=per_24, rounds=rounds, final=final,
                host=host, sni=sni, limit=limit, only=only, no_speed=no_speed, include=include,
                engine_id=engine_id, concurrency=concurrency, ranges_file=remote_ranges_file,
                exclude=exclude_inline, exclude_file=remote_exclude_file
            )
            cmd = ("ulimit -n 65535 2>/dev/null; "
                   f"timeout -k 10 {REMOTE_TIMEOUT} "
                   + shlex.join(args)
                   + " 2>&1 | tail -25")
            await log("در حال سنجش روی سرور ایران…" if only
                      else "در حال اسکن رنج کلادفلر از داخل ایران…")
            try:
                r = await asyncio.wait_for(conn.run(cmd, check=False), timeout=LOCAL_TIMEOUT)
            except (asyncio.TimeoutError, TimeoutError):
                try:
                    await conn.run(f"pkill -15 -f {shlex.quote(remote_script)} 2>/dev/null", check=False)
                    await asyncio.sleep(5)
                    await conn.run(f"pkill -9 -f {shlex.quote(remote_script)} 2>/dev/null", check=False)
                except Exception:
                    pass
                raise ScanTimeoutError(f"Scan timed out after {LOCAL_TIMEOUT}s on engine {engine_id}")

            tail = (r.stdout or "")[-500:]

            res = await conn.run(f"cat {shlex.quote(out_file + '.json')} 2>/dev/null", check=False)
            raw = (res.stdout or "").strip()
            if not raw:
                if getattr(r, "exit_status", None) == 124:
                    raise ScanTimeoutError(f"Scan timed out after {REMOTE_TIMEOUT}s on engine {engine_id}.\n{tail[-300:]}")
                raise RuntimeError(f"scanner produced no results.\n{tail[-300:]}")

            payload = json.loads(raw)
            if isinstance(payload, dict):
                file_start = payload.get("scan_start")
                file_engine = payload.get("engine_id")
                if file_start is not None and file_start < (scan_start_time - 5):
                    raise StaleResultError(
                        f"Stale scan results for engine {engine_id}: result timestamp {file_start} "
                        f"is older than scan start {scan_start_time}"
                    )
                if file_engine is not None and file_engine != engine_id and file_engine != 0:
                    raise StaleResultError(
                        f"Engine ID mismatch in scan results: expected {engine_id}, got {file_engine}"
                    )
                if payload.get("trust_store_broken"):
                    await log("هشدار: اعتبارسنجی گواهی SSL در سرور اسکنر با خطا مواجه شد (احتمال مشکل CA bundle یا ساعت سرور)")
                data = payload.get("results", [])
            elif isinstance(payload, list):
                data = payload
            else:
                raise RuntimeError(f"Unexpected scan result format: {type(payload)}")

            # keep only genuinely usable finalists (finite rtt), best first
            data = [d for d in data
                    if isinstance(d.get("rtt"), (int, float))
                    and math.isfinite(d["rtt"])]
            return data, tail
        finally:
            conn.close()


def is_better(candidate: dict, current_ip: str | None, current: dict | None,
              min_gain=0.15) -> bool:
    """
    Whether `candidate` is meaningfully better than the current best.

    A new IP has to beat the current one by a real margin (score, or loss),
    not by a hair of jitter that will flip back next scan - otherwise the bot
    would repoint the domain every hour on noise.
    """
    if current_ip is None or current is None:
        return True
    if candidate["ip"] == current_ip:
        return False
    c_loss = candidate.get("loss", 0) or 0
    o_loss = current.get("loss", 0) or 0
    # Loss dominates: any drop in loss is worth taking; a rise is never.
    if c_loss + 0.001 < o_loss:
        return True
    if c_loss > o_loss + 0.001:
        return False
    cs = _score(candidate)
    os_ = _score(current)
    return cs < os_ * (1 - min_gain)


def score(d: dict) -> float:
    """Public form of the ranking score, for callers that rank alongside us."""
    return _score(d)


def _score(d: dict) -> float:
    # Must agree exactly with cf_scan.score().
    rtt = d.get("rtt")
    if rtt is None or not math.isfinite(rtt):
        return float("inf")
    jit = float(d.get("jitter") or 0.0)
    loss = float(d.get("loss") or 0.0)
    tls_loss = float(d.get("tls_loss") or 0.0)
    tls_jitter = float(d.get("tls_jitter") or 0.0)
    mbps = float(d.get("mbps") or 0.0)
    cost = float(rtt) + 2.0 * jit + 1000.0 * loss + 1200.0 * tls_loss + 0.5 * tls_jitter
    if d.get("mbps"):
        cost -= min(float(d["mbps"]), 100.0) * 0.5
    return cost
