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
import os

import tunnel  # reuse the SSH connector (direct, or via the Iran jump)

SCANNER_LOCAL = os.path.join(os.path.dirname(__file__), "cf_scan.py")
REMOTE_SCANNER = "/root/cf_scan.py"
REMOTE_OUT = "/root/cf_bot_scan"


def _load_scanner() -> str:
    with open(SCANNER_LOCAL) as f:
        return f.read()


async def run_scan(ssh: dict, jump: dict | None, log, *, per_24=2, rounds=14,
                   final=20, host="speed.cloudflare.com"):
    """
    SSH to `ssh` (optionally via `jump`), run the scanner, return the ranked
    result list (best first). Each item: ip, rtt, jitter, loss, rtt_max, mbps.
    `log` is an async callable for progress.
    """
    conn = await tunnel.connect(ssh["host"], int(ssh.get("port", 22)),
                                ssh["user"], ssh["password"], jump=jump)
    try:
        await log("در حال آماده‌سازی اسکنر روی سرور ایران…")
        script = _load_scanner()
        # Write the scanner via SFTP so a 400-line file with quotes survives.
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(REMOTE_SCANNER, "w") as f:
                await f.write(script)

        # Raise the fd limit inline: every probe in flight holds one, and the
        # default 1024 would silently cap concurrency and lose candidates.
        cmd = (
            f"ulimit -n 65535 2>/dev/null; "
            f"python3 {REMOTE_SCANNER} --per-24 {per_24} --rounds {rounds} "
            f"--final {final} --host {host} --concurrency 500 "
            f"--out {REMOTE_OUT} 2>&1 | tail -25"
        )
        await log("در حال اسکن کل رنج کلادفلر از داخل ایران (حدود یک دقیقه)…")
        r = await asyncio.wait_for(conn.run(cmd, check=False), timeout=600)
        tail = (r.stdout or "")[-500:]

        res = await conn.run(f"cat {REMOTE_OUT}.json 2>/dev/null", check=False)
        raw = (res.stdout or "").strip()
        if not raw:
            raise RuntimeError(f"scanner produced no results.\n{tail[-300:]}")
        data = json.loads(raw)
        # keep only genuinely usable finalists (finite rtt), best first
        data = [d for d in data if isinstance(d.get("rtt"), (int, float))]
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


def _score(d: dict) -> float:
    rtt = d.get("rtt") or 999
    jit = d.get("jitter") or 0
    loss = d.get("loss") or 0
    mbps = d.get("mbps") or 0
    return rtt + 2 * jit + 1000 * loss - min(mbps, 100) * 0.5
