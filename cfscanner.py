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
import math
import os
import shlex
import time

import tunnel  # reuse the SSH connector (direct, or via the Iran jump)

SCANNER_LOCAL = os.path.join(os.path.dirname(__file__), "cf_scan.py")
REMOTE_OUT = "/root/cf_bot_scan"

REMOTE_TIMEOUT = 900
LOCAL_TIMEOUT = 960


class ScanTimeoutError(TimeoutError):
    pass


class StaleResultError(RuntimeError):
    pass


def _load_scanner() -> str:
    with open(SCANNER_LOCAL) as f:
        return f.read()


def _build_scan_args(remote_scanner: str, out_file: str, *, per_24=2, rounds=14,
                     final=20, host="speed.cloudflare.com", sni: str | None = None,
                     limit=0, only=None, no_speed=False, include=None, engine_id: int = 0) -> list[str]:
    args = ["python3", remote_scanner,
            "--per-24", str(per_24),
            "--rounds", str(rounds),
            "--final", str(final),
            "--host", host,
            "--concurrency", "500",
            "--out", out_file]
    if engine_id:
        args += ["--engine-id", str(engine_id)]
    if sni:
        args += ["--sni", sni]
    if limit:
        args += ["--limit", str(int(limit))]
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
                   remote_out: str | None = None):
    """
    SSH to `ssh` (optionally via `jump`), run the scanner, return the ranked
    result list (best first). Each item: ip, rtt, jitter, loss, rtt_max, mbps.
    `log` is an async callable for progress.
    `engine_id` isolates output files on the remote server when multiple engines scan.
    `sni` allows probing with the actual domain SNI.
    """
    remote_script = f"/root/.cf_scan_engine_{engine_id}.py"
    tmp_path = f"{remote_script}.tmp.{os.getpid()}"
    out_file = remote_out or (f"/root/cf_bot_scan_engine_{engine_id}" if engine_id else REMOTE_OUT)
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
        # Write the scanner via SFTP to a unique temp path, then atomically rename into per-engine path
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(tmp_path, "w") as f:
                await f.write(script)
        await conn.run(f"mv {shlex.quote(tmp_path)} {shlex.quote(remote_script)}", check=False)

        # Raise the fd limit inline: every probe in flight holds one, and the
        # default 1024 would silently cap concurrency and lose candidates.
        args = _build_scan_args(
            remote_script, out_file, per_24=per_24, rounds=rounds, final=final,
            host=host, sni=sni, limit=limit, only=only, no_speed=no_speed, include=include,
            engine_id=engine_id
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
    mbps = float(d.get("mbps") or 0.0)
    return rtt + 2.0 * jit + 1000.0 * loss + 1200.0 * tls_loss - min(mbps, 100.0) * 0.5
