"""
Run the endpoint probes from inside Iran and decide when to shout.

Same reasoning as the clean-IP scanner: a config's health has to be measured
from where the customers are, so the probe script is shipped to an Iran relay
over SSH and run there. What comes back is a verdict per endpoint.

Alerting is deliberately slow to fire and quick to clear. Iranian transit has
bad minutes that recover on their own, and a watchdog that pages on every one
of them gets muted within a week - at which point it protects nothing. So a
target must fail FAIL_STREAK consecutive rounds before anyone is told, while a
recovery is announced immediately.
"""
import asyncio
import json
import os

import tunnel

PROBE_LOCAL = os.path.join(os.path.dirname(__file__), "probe.py")
REMOTE_PROBE = "/root/pg_probe.py"

FAIL_STREAK = 2          # consecutive bad rounds before alerting
BAD = ("down", "filtered", "degraded")


async def run_probes(ssh: dict, jump: dict | None, targets: list) -> list:
    """SSH to the Iran relay, probe every target, return the result list."""
    if not targets:
        return []
    conn = await tunnel.connect(ssh["host"], int(ssh.get("port", 22)),
                                ssh["user"], ssh["password"], jump=jump)
    try:
        with open(PROBE_LOCAL) as f:
            script = f.read()
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(REMOTE_PROBE, "w") as f:
                await f.write(script)

        payload = json.dumps(targets)
        r = await asyncio.wait_for(
            conn.run(f"python3 {REMOTE_PROBE}", input=payload, check=False),
            timeout=300)
        out = (r.stdout or "").strip()
        if not out:
            raise RuntimeError((r.stderr or "probe produced no output")[-300:])
        return json.loads(out)
    finally:
        conn.close()


def evaluate(results: list, state: dict):
    """
    Fold new results into the stored alert state.

    Returns (events, new_state). Each event is
    {kind: 'bad'|'recovered', target, verdict, prev}.
    """
    events = []
    new_state = dict(state or {})
    for r in results:
        key = str(r.get("id"))
        prev = new_state.get(key, {"streak": 0, "firing": False,
                                   "verdict": "healthy"})
        verdict = r.get("verdict", "down")
        bad = verdict in BAD

        if bad:
            streak = prev["streak"] + 1
            if streak >= FAIL_STREAK and not prev["firing"]:
                events.append({"kind": "bad", "target": r, "verdict": verdict,
                               "prev": prev.get("verdict")})
                new_state[key] = {"streak": streak, "firing": True,
                                  "verdict": verdict}
            elif prev["firing"] and verdict != prev.get("verdict"):
                # It is still broken but in a different way (e.g. degraded ->
                # filtered); worth saying once, without re-firing the alert.
                events.append({"kind": "bad", "target": r, "verdict": verdict,
                               "prev": prev.get("verdict")})
                new_state[key] = {"streak": streak, "firing": True,
                                  "verdict": verdict}
            else:
                new_state[key] = {"streak": streak, "firing": prev["firing"],
                                  "verdict": verdict}
        else:
            if prev["firing"]:
                events.append({"kind": "recovered", "target": r,
                               "verdict": verdict, "prev": prev.get("verdict")})
            new_state[key] = {"streak": 0, "firing": False, "verdict": verdict}
    return events, new_state


VERDICT_FA = {
    "healthy": "🟢 سالم",
    "degraded": "🟡 ضعیف",
    "filtered": "🔴 فیلتر شده",
    "down": "⚫️ قطع",
}


def describe(r: dict) -> str:
    v = VERDICT_FA.get(r.get("verdict"), r.get("verdict", "?"))
    bits = [v]
    tcp = r.get("tcp_ratio")
    if tcp is not None:
        bits.append(f"TCP {round(tcp * 100)}%")
    if r.get("tcp_ms"):
        bits.append(f"{r['tcp_ms']}ms")
    if r.get("tls"):
        tls = r.get("tls_ratio")
        if tls is not None:
            bits.append(f"TLS {round(tls * 100)}%")
    if r.get("error"):
        bits.append(str(r["error"]))
    return " · ".join(bits)
