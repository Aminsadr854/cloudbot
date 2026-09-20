"""
Independent Cloudflare IP Scanner Engine Architecture.

Implements 3 completely independent and parallel scanning engines (Engine 1, Engine 2, Engine 3)
with isolated state, configuration, remote execution, and Cloudflare domain targeting.
Coordinates phone delivery with an isolated 5-minute offset queue.
"""
import asyncio
import html
import json
import logging
import os
import ssl
import time
from typing import Callable, Optional

import cfscanner
from cloudflare import Cloudflare
from store import Store

log = logging.getLogger("scanner_engine")

SCAN_SAMPLE = 1000        # addresses the relay measures in one pass
PHONE_SHORTLIST = 50      # the best of a window, handed to the phones
PHONE_GRACE_MINUTES = 25  # how long a fresh list waits for the handsets
SCAN_GAP_MINUTES = 10     # between passes of the round-the-clock scan
MAX_RESHORTLIST = 4       # fresh shortlists per window before giving pool a rest
REQUIRED_PHONES = 2       # handsets that must both approve an address
HEAD_TO_HEAD_TTL = 20 * 60
HEAD_TO_HEAD_MAX = 5
REPORT_TTL = 7 * 86400
DELIVERY_OFFSET_SECONDS = 5 * 60  # 5 minutes offset between engine phone deliveries

TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE
TLS_CTX.set_alpn_protocols(["http/1.1"])


def get_engine_targets(st: Store, engine_id: int) -> tuple[str, str]:
    """
    Returns (host, sni) for a specific engine, fully isolated.
    """
    return st.get_engine_targets(engine_id)


async def verify_domain_ip(ip: str, host: str, sni: str, port: int = 443, timeout: float = 6.0) -> tuple[bool, str]:
    """
    Validates whether the actual configured domain works through candidate IP.
    Connects to ip:port, sets TLS SNI to sni, sends HTTP GET with Host: host.
    Returns (is_valid, reason).
    """
    server_name = (sni or host).strip()
    try:
        fut = asyncio.open_connection(ip, port, ssl=TLS_CTX, server_hostname=server_name)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)

        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()

        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        headers = head.decode("latin1", "replace").lower()
        status = head.split(b" ")[1].decode() if b" " in head else "?"

        raw_body = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        body = raw_body.decode("latin1", "replace").lower()

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # 1. Reject Cloudflare errors
        cf_errors = ["1034", "1000", "1001", "1002", "520", "521", "522", "523", "524", "525", "526"]
        for code in cf_errors:
            if f"error code: {code}" in body or f"errorcode: {code}" in body or f"error {code}" in body:
                return False, f"Cloudflare Error {code}"

        if status == "403" and ("cloudflare" in headers or "cf-ray" in headers) and "error" in body:
            return False, "Cloudflare 403 Edge Restriction"

        # 2. Check for valid origin / application responses
        if status in ("200", "101"):
            return True, f"HTTP {status} OK"
        if status == "400" and ("sec-websocket-version" in headers or "bad request" in body):
            return True, "Valid WebSocket Backend (HTTP 400)"
        if status in ("204", "301", "302", "404") and not ("error" in body and "cloudflare" in headers):
            return True, f"HTTP {status} from Origin"

        return False, f"Unexpected response: HTTP {status}"
    except Exception as e:
        return False, f"Connection/TLS failed: {type(e).__name__} ({e})"


def _control_ips() -> list:
    """The reference address handed to phones alongside real candidates."""
    probe_base = os.environ.get(
        "CLOUDBOT_PROBE_BASE",
        os.environ.get("CLOUDBOT_PROBE", "https://status.etesalpaya.com")
    )
    host = probe_base.split("//", 1)[-1].split("/")[0].split(":")[0]
    try:
        import socket
        return [socket.gethostbyname(host)]
    except Exception:
        return []


def _report_trusted(rep: dict, controls: set) -> tuple[bool, str]:
    """Whether a round says anything about the addresses -> (trusted, why)."""
    res = rep.get("results") or []
    if not res:
        return False, "چیزی اندازه‌گیری نشده بود"
    if (rep.get("net") or "cellular") != "cellular":
        return False, "روی وای‌فای اندازه‌گیری شده بود، نه دیتای همراه"
    seen = [r for r in res if r.get("ip") in controls]
    if seen:
        if not any(r.get("ok") for r in seen):
            return False, "سرور ایران هم از این گوشی جواب نداد — اینترنت گوشی قطع بوده"
        return True, ""
    if not any(r.get("ok") for r in res):
        return False, "هیچ آدرسی جواب نداد و مرجعی نداشت"
    return True, ""


def _classify_reports(st: Store, engine_id: int = 1):
    now = int(time.time())
    cand = st.scan_candidates(engine_id=engine_id)
    controls = set(cand.get("controls") or [])
    cand_hash = st.candidate_set_hash(cand.get("ips", []), cand.get("controls", []))
    trusted, aside = {}, {}
    for d, r in st.device_reports(engine_id=engine_id).items():
        if now - (r.get("ts") or 0) >= REPORT_TTL:
            continue
        ok, why = _report_trusted(r, controls)
        if not ok:
            aside[d] = (r, why)
            continue
        # Candidate set hash verification: report must match engine's current shortlist
        rep_ips = [x.get("ip") for x in (r.get("results") or []) if x.get("ip")]
        rep_hash = st.candidate_set_hash(rep_ips, controls)
        if cand_hash and rep_hash != cand_hash:
            aside[d] = (r, f"Candidate set hash mismatch (expected {cand_hash}, got {rep_hash})")
            continue
        trusted[d] = r
    return trusted, aside


def _fresh_reports(st: Store, engine_id: int = 1) -> dict:
    return _classify_reports(st, engine_id=engine_id)[0]


def _device_scoring(results: list, controls=()) -> dict:
    results = [r for r in results if r.get("ip") not in controls]
    live = [r for r in results if r.get("rtt_ms") and r.get("ok")]
    if not live:
        return {}
    rtts = sorted(r["rtt_ms"] for r in live)
    median = rtts[len(rtts) // 2]
    losses = sorted((r.get("loss") or 0) for r in live)
    median_loss = losses[len(losses) // 2]

    out = {}
    for r in results:
        ip = r.get("ip")
        if not ip:
            continue
        rtt = r.get("rtt_ms")
        loss = r.get("loss") or 0
        if not r.get("ok") or not rtt:
            out[ip] = (False, rtt, None)
            continue
        rel = rtt / median if median else 1.0
        good = rel <= 1.15 and loss <= max(0.25, median_loss + 0.10)
        out[ip] = (good, rtt, rel)
    return out


def _phone_verdicts(st: Store, since=0, engine_id: int = 1) -> dict:
    cand = st.scan_candidates(engine_id=engine_id)
    controls = set(cand.get("controls") or [])
    return {d: _device_scoring(r.get("results", []), controls)
            for d, r in _fresh_reports(st, engine_id=engine_id).items()
            if int(r.get("ts") or 0) >= int(since or 0)}


def _record_blocked(st: Store, engine_id: int = 1) -> set:
    cand = st.scan_candidates(engine_id=engine_id)
    controls = set(cand.get("controls") or [])
    bad, good = set(), set()
    for _d, r in _fresh_reports(st, engine_id=engine_id).items():
        for x in r.get("results") or []:
            ip = x.get("ip")
            if not ip or ip in controls:
                continue
            (good if x.get("ok") else bad).add(ip)
    bad -= good
    if bad:
        st.mark_blocked(bad)
    return bad


def choose(results: list, live_ip: Optional[str] = None, measured: Optional[dict] = None,
           since: int = 0, engine_id: int = 1, st: Optional[Store] = None) -> dict:
    """
    Select whether to move the domain and to which address for a specific engine.
    """
    if st is None:
        st = Store()
    ranked = [r for r in results if r.get("ip")]
    on_list = {r["ip"] for r in ranked}
    live_entry = next((r for r in ranked if r["ip"] == live_ip), None)

    def keep(why, voters=0, needs=None):
        return {"change": False, "entry": live_entry, "why": why,
                "voters": voters, "needs_measure": needs or []}

    if not ranked:
        return keep("لیست کاندید خالی است — آدرس فعلی ماند")

    verdicts = {d: {ip: v for ip, v in vs.items() if ip in on_list}
                for d, vs in _phone_verdicts(st, since=since, engine_id=engine_id).items()}
    voters = [d for d, v in verdicts.items() if v]
    if len(voters) < REQUIRED_PHONES:
        return keep(f"فقط {len(voters)} از {REQUIRED_PHONES} گوشی این لیست را سنجیده؛ "
                    f"تعویض فقط با تأیید هر دو گوشی — آدرس فعلی ماند", len(voters))

    approved = []
    for r in ranked:
        opinions = [verdicts[d].get(r["ip"]) for d in voters]
        if any(o is None for o in opinions) or not all(o[0] for o in opinions):
            continue
        rels = [o[2] for o in opinions if o[2]]
        approved.append(((sum(rels) / len(rels)) if rels else 9, r))
    if not approved:
        return keep("هیچ آدرسی تأیید هر دو گوشی را نگرفت — آدرس فعلی ماند", len(voters))
    approved.sort(key=lambda x: x[0])

    if live_ip and any(r["ip"] == live_ip for _rel, r in approved):
        return keep("آدرس فعلی خودش مورد تأیید هر دو گوشی است", len(voters))

    contenders = [(rel, r) for rel, r in approved if r["ip"] != live_ip][:HEAD_TO_HEAD_MAX]
    if measured is None:
        return keep("در انتظار مقایسهٔ سرور با آدرس فعلی", len(voters),
                    [r["ip"] for _rel, r in contenders])

    live_m = measured.get(live_ip) if live_ip else None
    if live_ip and live_m is None:
        return keep("اندازه‌گیری آدرس فعلی ناموفق بود — آدرس فعلی ماند",
                    len(voters))
    if live_m and (live_m.get("cf_error") or live_m.get("valid") is False):
        live_score = float("inf")
    elif live_m:
        live_score = cfscanner.score(live_m)
    else:
        live_score = float("inf")   # only when there is no live_ip at all

    better = []
    for rel, r in contenders:
        m = measured.get(r["ip"])
        if not m:
            continue
        if m.get("cf_error") or m.get("valid") is False:
            continue
        if cfscanner.score(m) < live_score:
            better.append((rel, cfscanner.score(m), r, m))
    if not better:
        return keep(f"{len(contenders)} آدرس تأیید هر دو گوشی را گرفت ولی در تست سرور هیچ‌کدام "
                    f"از آدرس فعلی بهتر نبود — آدرس فعلی ماند", len(voters))

    better.sort(key=lambda x: (x[0], x[1]))
    live_txt = ("%.0f" % live_score) if live_m else "بی‌پاسخ"
    contenders_ranked = []
    for rel, sc, r, m in better:
        entry = dict(r, **m)
        entry["ip"] = r["ip"]
        why = (f"هر دو گوشی تأییدش کردند ({rel:.2f}) و در تست سرور از آدرس فعلی بهتر بود "
               f"(امتیاز {sc:.0f} در برابر {live_txt})")
        contenders_ranked.append((entry, why))

    entry, why = contenders_ranked[0]
    return {"change": True, "entry": entry, "why": why,
            "contenders": contenders_ranked,
            "voters": len(voters), "needs_measure": []}


async def _head_to_head(st: Store, since: int, live_ip: Optional[str],
                        ips: list, engine_id: int = 1) -> Optional[dict]:
    """Measure live address and contenders together in one relay run for this engine."""
    key = "%s|%s|%s" % (since, live_ip or "", ",".join(sorted(ips)))
    cached = st.scan_h2h(engine_id=engine_id)
    if cached.get("key") == key and time.time() - (cached.get("ts") or 0) < HEAD_TO_HEAD_TTL:
        return cached.get("measured") or {}

    ssh = st.cfscan(engine_id=engine_id).get("ssh")
    if not ssh:
        return None
    only = ([live_ip] if live_ip else []) + [ip for ip in ips if ip != live_ip]
    host, sni = st.get_engine_targets(engine_id)

    async def hlog(t):
        log.info("[ENGINE %d] head-to-head: %s", engine_id, t)

    try:
        rows, _tail = await cfscanner.run_scan(
            ssh, st.jump(), hlog, only=only, final=len(only), engine_id=engine_id,
            host=host, sni=sni)
    except Exception:
        log.exception("[ENGINE %d] head-to-head measurement failed", engine_id)
        return None

    measured = {r["ip"]: {k: v for k, v in r.items() if k != "ip"} for r in rows if r.get("ip")}
    st.set_scan_h2h({"key": key, "ts": int(time.time()), "measured": measured}, engine_id=engine_id)
    log.info("[ENGINE %d] head-to-head %s -> %s", engine_id, key,
             {ip: round(cfscanner.score(m)) for ip, m in measured.items()})
    return measured


async def decide(st: Store, results: list, live_ip: Optional[str], cand: dict,
                 engine_id: int = 1) -> dict:
    """choose(), taking relay comparison first when phones agreed for this engine."""
    since = int(cand.get("ts") or 0)
    d = choose(results, live_ip, since=since, engine_id=engine_id, st=st)
    if not d["needs_measure"]:
        return d
    measured = await _head_to_head(st, since, live_ip, d["needs_measure"], engine_id=engine_id)
    if measured is None:
        d["why"] = "مقایسهٔ سرور با آدرس فعلی انجام نشد — آدرس فعلی ماند"
        return d
    return choose(results, live_ip, measured=measured, since=since, engine_id=engine_id, st=st)


class PhoneDeliveryCoordinator:
    """
    Coordinates phone delivery with strict 5-minute offset between engines.
    Engine 1 -> T
    Engine 2 -> T + 5 min
    Engine 3 -> T + 10 min

    The delay only applies to delivery scheduling; it never blocks scanning.
    """
    def __init__(self, offset_seconds: int = DELIVERY_OFFSET_SECONDS):
        self.offset_seconds = offset_seconds
        self._lock = asyncio.Lock()
        self._last_delivery_time = 0.0
        self._next_slot_time = 0.0
        self._queue: list[dict] = []
        self._active_engine: Optional[int] = None

    async def schedule_delivery(self, engine_id: int, log_callback: Optional[Callable] = None) -> float:
        async with self._lock:
            now = time.time()
            base = max(now, self._last_delivery_time + self.offset_seconds, self._next_slot_time)
            if base <= now:
                scheduled_time = now
                self._next_slot_time = now + self.offset_seconds
            else:
                scheduled_time = base
                self._next_slot_time = base + self.offset_seconds

            delay = max(0.0, scheduled_time - now)
            self._queue = [e for e in self._queue if e["engine_id"] != engine_id]
            self._queue.append({"engine_id": engine_id, "scheduled_time": scheduled_time})

        if delay > 0:
            mins = int(round(delay / 60.0))
            mins = max(1, mins)
            msg = f"[ENGINE {engine_id}] Scheduled delivery in {mins} minutes"
            log.info(msg)
            if log_callback:
                await log_callback(msg)
            await asyncio.sleep(delay)

        async with self._lock:
            self._last_delivery_time = time.time()
            self._active_engine = engine_id
            self._queue = [e for e in self._queue if e["engine_id"] != engine_id]

        msg = f"[ENGINE {engine_id}] Sending result to phones"
        log.info(msg)
        if log_callback:
            await log_callback(msg)
        return self._last_delivery_time

    def get_queue_info(self, engine_id: int) -> dict:
        now = time.time()
        for e in self._queue:
            if e["engine_id"] == engine_id:
                delay = max(0.0, e["scheduled_time"] - now)
                return {"queued": True, "eta_seconds": delay, "eta_minutes": int(round(delay / 60.0))}
        return {"queued": False, "eta_seconds": 0, "eta_minutes": 0}


# Global delivery coordinator shared across engines
delivery_coordinator = PhoneDeliveryCoordinator()


class ScannerEngine:
    """
    Independent scanner engine instance.
    Runs its own schedule, pool, candidate generation, phone delivery, and DNS updates.
    """
    def __init__(self, engine_id: int, store: Optional[Store] = None,
                 coordinator: Optional[PhoneDeliveryCoordinator] = None,
                 verifier: Optional[Callable] = None):
        self.engine_id = engine_id
        self.name = f"ENGINE_{engine_id}"
        self.st = store or Store()
        self.coordinator = coordinator or delivery_coordinator
        self.verifier = verifier
        self.lock = asyncio.Lock()  # Per-engine scan lock
        self._running = False

    def get_status(self) -> dict:
        status = self.st.engine_status(self.engine_id)
        q_info = self.coordinator.get_queue_info(self.engine_id)
        if q_info["queued"]:
            status["state"] = "waiting_delivery"
            status["eta_minutes"] = q_info["eta_minutes"]
        return status

    def set_status(self, state: str, detail: str = ""):
        self.st.set_engine_status(self.engine_id, state, detail)

    async def scan_pass(self, log_fn: Callable) -> int:
        """One pass of the continuous scan for this engine."""
        cfg = self.st.cfscan(self.engine_id)
        ssh = cfg.get("ssh")
        if not ssh:
            return 0
        log.info("[ENGINE %d] Starting scan pass", self.engine_id)
        self.set_status("scanning", "اسکن رنج کلادفلر")
        host, sni = self.st.get_engine_targets(self.engine_id)
        results, _tail = await cfscanner.run_scan(
            ssh, self.st.jump(), log_fn, limit=SCAN_SAMPLE,
            final=PHONE_SHORTLIST, no_speed=True, engine_id=self.engine_id,
            host=host, sni=sni)
        self.st.pool_add(results, engine_id=self.engine_id)
        log.info("[ENGINE %d] Candidate IPs: %d", self.engine_id, len(results))
        self.set_status("idle", f"{len(results)} آدرس به استخر اضافه شد")
        return len(results)

    async def close_window(self, log_fn: Callable, *, apply_if_better: bool = False):
        """Finish scan window, re-measure finalists, and schedule delivery to phones."""
        cfg = self.st.cfscan(self.engine_id)
        pool = self.st.scan_pool(self.engine_id)
        blocked = self.st.blocked_ips()
        entries = [dict(m, ip=ip) for ip, m in (pool.get("ips") or {}).items()
                   if ip not in blocked]
        if not entries:
            entries = [dict(m, ip=ip) for ip, m in (pool.get("ips") or {}).items()]
        if not entries:
            raise RuntimeError(f"[ENGINE {self.engine_id}] استخر اسکن خالی است")

        entries.sort(key=cfscanner.score)
        top = [e["ip"] for e in entries[:PHONE_SHORTLIST]]
        await log_fn(f"[ENGINE {self.engine_id}] پایان پنجره: {len(entries)} آدرس — "
                     f"{len(top)} برتر سنجیده می‌شوند")

        ssh = cfg.get("ssh")
        host, sni = self.st.get_engine_targets(self.engine_id)
        results, _tail = await cfscanner.run_scan(
            ssh, self.st.jump(), log_fn, only=top, final=PHONE_SHORTLIST,
            engine_id=self.engine_id,
            host=host, sni=sni)
        if not results:
            results = entries[:PHONE_SHORTLIST]
        results.sort(key=cfscanner.score)
        shortlist = results[:PHONE_SHORTLIST]

        # Schedule phone delivery via the 5-minute offset queue
        self.set_status("waiting_delivery", "در صف ارسال به گوشی‌ها")
        await self.coordinator.schedule_delivery(self.engine_id, log_callback=log_fn)

        # Delivered to phones
        self.st.set_scan_candidates(shortlist, _control_ips(), keep=PHONE_SHORTLIST,
                                    engine_id=self.engine_id)
        self.st.set_candidate_meta(engine_id=self.engine_id,
                                   tried=[e["ip"] for e in shortlist], reshortlists=0)
        self.st.pool_reset(engine_id=self.engine_id)
        self.set_status("testing", "منتظر گزارش گوشی‌ها")

        fqdn = cfg.get("fqdn")
        live_ip = None
        if fqdn and self.st.cf_token():
            try:
                cf = Cloudflare(self.st.cf_token())
                zone = await cf.zone_for(fqdn)
                rec = await cf.find_a_record(zone[0], fqdn) if zone else None
                live_ip = rec["content"] if rec else None
            except Exception as e:
                await log_fn(f"[ENGINE {self.engine_id}] ⚠️ خطای دامنه: {html.escape(str(e)[:150])}")

        keep_entry = next((r for r in shortlist if r["ip"] == live_ip), None)
        fields = {"last_scan_ts": int(time.time())}
        if keep_entry:
            fields.update(last_best_ip=keep_entry["ip"], last_best=keep_entry)
        self.st.update_cfscan(self.engine_id, **fields)
        return (keep_entry or shortlist[0]), False, False, "منتظر سنجش گوشی‌ها"

    async def reshortlist(self, log_fn: Callable) -> bool:
        """Hand phones the next untried batch if all addresses were refused."""
        cand = self.st.scan_candidates(engine_id=self.engine_id)
        tried = set(cand.get("tried") or []) | set(cand.get("ips") or [])
        rounds = int(cand.get("reshortlists") or 0)
        if rounds >= MAX_RESHORTLIST:
            await log_fn(f"[ENGINE {self.engine_id}] سقف لیست‌های جایگزین پر شد")
            return False

        blocked = self.st.blocked_ips()
        pool = self.st.scan_pool(engine_id=self.engine_id).get("ips") or {}
        fresh = [dict(m, ip=ip) for ip, m in pool.items()
                 if ip not in tried and ip not in blocked]
        if len(fresh) < 5:
            await log_fn(f"[ENGINE {self.engine_id}] آدرس نیازمودهٔ کافی در استخر نیست")
            return False

        fresh.sort(key=cfscanner.score)
        batch = fresh[:PHONE_SHORTLIST]
        self.st.set_scan_candidates(batch, _control_ips(), keep=PHONE_SHORTLIST,
                                    engine_id=self.engine_id)
        self.st.set_candidate_meta(engine_id=self.engine_id,
                                   tried=sorted(tried | {e["ip"] for e in batch}),
                                   reshortlists=rounds + 1)
        await log_fn(f"[ENGINE {self.engine_id}] لیست جایگزین #{rounds + 1}: {len(batch)} آدرس تازه")
        return True

    async def phone_recheck_pass(self, notify_fn: Optional[Callable] = None,
                                 verifier: Optional[Callable] = None):
        """Evaluate phone reports, choose best IP, and update Cloudflare domain for this engine."""
        _verify = verifier or self.verifier or verify_domain_ip
        cfg = self.st.cfscan(self.engine_id)
        cand = self.st.scan_candidates(engine_id=self.engine_id)
        if time.time() - (cand.get("ts") or 0) > 12 * 3600:
            return  # candidate list too old
        metrics = cand.get("metrics") or {}
        results = [dict(metrics[ip], ip=ip) for ip in cand.get("ips", [])
                   if metrics.get(ip, {}).get("rtt")]
        if not results:
            return
        results.sort(key=cfscanner.score)

        fqdn = cfg.get("fqdn")
        cf = zone = rec = None
        live_ip = None
        if fqdn and self.st.cf_token():
            try:
                cf = Cloudflare(self.st.cf_token())
                zone = await cf.zone_for(fqdn)
                rec = await cf.find_a_record(zone[0], fqdn) if zone else None
                live_ip = rec["content"] if rec else None
            except Exception as e:
                log.warning("[ENGINE %d] Cloudflare zone lookup failed: %s", self.engine_id, e)

        blocked_now = _record_blocked(self.st, engine_id=self.engine_id)
        on_list = {r["ip"] for r in results}
        fresh_reps = _fresh_reports(self.st, engine_id=self.engine_id)
        usable = any(
            x.get("ok") and x.get("ip") in on_list
            for r in fresh_reps.values()
            for x in (r.get("results") or []))

        if not usable and on_list and on_list <= blocked_now:
            async def rlog(t):
                log.info("[ENGINE %d] reshortlist: %s", self.engine_id, t)
            if await self.reshortlist(rlog):
                return

        d = await decide(self.st, results, live_ip, cand, engine_id=self.engine_id)
        decision_key = f"scan_last_decision_engine_{self.engine_id}"
        if d["why"] != self.st.get(decision_key):
            self.st.set(decision_key, d["why"])
            log.info("[ENGINE %d] Decision (live %s, %d phones): %s",
                     self.engine_id, live_ip, d["voters"], d["why"])

        if not d["change"]:
            return

        contenders_to_try = d.get("contenders") or ([(d["entry"], d["why"])] if d.get("entry") else [])
        target_host, target_sni = self.st.get_engine_targets(self.engine_id)
        confirmed_chosen = None
        confirmed_why = None

        for chosen_cand, why_cand in contenders_to_try:
            # 1. DOMAIN_PREVALIDATED: Candidate must prove domain validity BEFORE touching DNS
            pre_ok, pre_reason = await _verify(chosen_cand["ip"], host=target_host, sni=target_sni)
            if not pre_ok:
                log.warning("[ENGINE %d] DOMAIN_PREVALIDATION failed for candidate %s: %s (trying next contender)",
                            self.engine_id, chosen_cand["ip"], pre_reason)
                continue

            log.info("[ENGINE %d] DOMAIN_PREVALIDATED for %s: %s", self.engine_id, chosen_cand["ip"], pre_reason)
            confirmed_chosen = chosen_cand
            confirmed_why = why_cand
            break

        if not confirmed_chosen:
            fail_msg = f"هیچ‌کدام از {len(contenders_to_try)} کاندید برتر در تست اعتبارسنجی دامنه تأیید نشدند"
            self.st.set(decision_key, fail_msg)
            log.warning("[ENGINE %d] %s", self.engine_id, fail_msg)
            return

        chosen, why = confirmed_chosen, confirmed_why

        applied = False
        previous_live_ip = live_ip

        if cfg.get("auto_apply") and fqdn and self.st.cf_token() and cf and zone:
            # 2. DNS_UPDATED: Apply to Cloudflare
            try:
                if rec:
                    await cf.update_a(zone[0], rec, chosen["ip"])
                else:
                    await cf.create_a(zone[0], fqdn, chosen["ip"], proxied=False)
                applied = True
                log.info("[ENGINE %d] DNS_UPDATED: %s -> %s (previous: %s)",
                         self.engine_id, fqdn, chosen["ip"], previous_live_ip)
            except Exception as e:
                log.error("[ENGINE %d] DNS update failed: %s", self.engine_id, e)
                if notify_fn:
                    await notify_fn(
                        f"⚠️ <b>[موتور {self.engine_id}] خطای کلادفلر در اعمال DNS</b>\n\n"
                        f"دامنه: <code>{fqdn}</code>\nخطا: <code>{html.escape(str(e)[:200])}</code>")
                return

            # 3. DOMAIN_POSTCONFIRMED: Post-DNS confirmation with automated rollback
            await asyncio.sleep(6.0)
            post_ok, post_reason = await _verify(chosen["ip"], host=target_host, sni=target_sni)
            if not post_ok:
                log.error("[ENGINE %d] DOMAIN_POSTCONFIRMED failed for %s: %s. Initiating automatic rollback!",
                          self.engine_id, chosen["ip"], post_reason)
                rollback_done = False
                if previous_live_ip:
                    try:
                        cur_rec = await cf.find_a_record(zone[0], fqdn)
                        if cur_rec:
                            await cf.update_a(zone[0], cur_rec, previous_live_ip)
                            rollback_done = True
                            log.info("[ENGINE %d] Automatic rollback to %s succeeded", self.engine_id, previous_live_ip)
                    except Exception as rb_err:
                        log.error("[ENGINE %d] Automatic rollback failed: %s", self.engine_id, rb_err)
                if notify_fn:
                    rb_txt = f"بازگشت خودکار به <code>{previous_live_ip}</code> انجام شد." if rollback_done else "بازگشت خودکار ناموفق بود!"
                    await notify_fn(
                        f"🚨 <b>[موتور {self.engine_id}] خطا در تست پس از DNS — بازگشت خودکار</b>\n\n"
                        f"دامنه: <code>{fqdn}</code>\n"
                        f"آدرس کاندید: <code>{chosen['ip']}</code>\n"
                        f"علت: <code>{html.escape(post_reason)}</code>\n"
                        f"{rb_txt}")
                return

            log.info("[ENGINE %d] DOMAIN_POSTCONFIRMED succeeded for %s", self.engine_id, chosen["ip"])

        # 4. BEST_CONFIRMED: Only reached if domain prevalidation (and post-DNS confirmation if auto_apply) passed!
        log.info("[ENGINE %d] BEST_CONFIRMED: %s", self.engine_id, chosen["ip"])
        self.st.update_cfscan(self.engine_id, last_best_ip=chosen["ip"], last_best=chosen)
        if applied:
            self.st.add_found_ip({**chosen, "applied": True, "by_phone": True,
                                  "phones": d["voters"]}, engine_id=self.engine_id)

        suggested_key = f"scan_suggested_engine_{self.engine_id}"
        if not applied and self.st.get(suggested_key) == "%s|%s" % (cand.get("ts"), chosen["ip"]):
            return
        self.st.set(suggested_key, "%s|%s" % (cand.get("ts"), chosen["ip"]))

        if notify_fn:
            head = (f"🔄 <b>[موتور {self.engine_id}] آی‌پی دامنه عوض شد</b>"
                    if applied else f"⭐️ <b>[موتور {self.engine_id}] آی‌پی تازه آماده است</b>")
            dom_text = f"\n🌐 دامنه: <code>{fqdn}</code>" if fqdn else ""
            msg = (f"{head}{dom_text}\n\n"
                   f"از <code>{live_ip or '—'}</code> به <code>{chosen['ip']}</code>\n"
                   f"{why}\n"
                   f"rtt: {chosen.get('rtt')}ms · jitter: {chosen.get('jitter')}ms · "
                   f"loss: {round((chosen.get('loss') or 0)*100)}%")
            if not applied:
                msg += "\n\n<i>اعمال خودکار خاموش است؛ روی دامنه ثبت نشد.</i>"
            await notify_fn(msg)

    async def scan_loop(self, notify_fn: Optional[Callable] = None):
        """Continuous scheduler loop for this engine."""
        self._running = True
        log.info("[ENGINE %d] Starting scheduler loop", self.engine_id)
        await asyncio.sleep(10 + self.engine_id * 5)  # slight stagger at initial boot
        while self._running:
            gap = SCAN_GAP_MINUTES * 60
            try:
                cfg = self.st.cfscan(self.engine_id)
                if not cfg.get("ssh"):
                    self.set_status("idle", "سرور اسکن تنظیم نشده")
                    await asyncio.sleep(gap)
                    continue

                async with self.lock:
                    async def qlog(t):
                        log.info("[ENGINE %d] scan: %s", self.engine_id, t)

                    pool = self.st.scan_pool(self.engine_id)
                    iv = cfg.get("interval_hours") or 6
                    started = pool.get("started") or 0
                    if not started:
                        self.st.pool_reset(self.engine_id)
                        started = time.time()

                    found = await self.scan_pass(qlog)
                    log.info("[ENGINE %d] Scan pass finished: %d addresses into pool (%d in window)",
                             self.engine_id, found, len(self.st.scan_pool(self.engine_id).get("ips") or {}))

                    if time.time() - started >= iv * 3600:
                        best, changed, applied, why = await self.close_window(
                            qlog, apply_if_better=cfg.get("auto_apply"))
                        if notify_fn and (changed or applied):
                            fqdn = cfg.get("fqdn") or "—"
                            head = f"🎉 <b>[موتور {self.engine_id}] آی‌پی انتخابی ثبت شد</b>"
                            msg = (f"{head}\n\n🌐 دامنه: <code>{fqdn}</code>\n"
                                   f"⭐️ <code>{best['ip']}</code> — {html.escape(why)}")
                            await notify_fn(msg)
            except Exception as e:
                log.exception("[ENGINE %d] Scan scheduler pass failed: %s", self.engine_id, e)
                self.set_status("error", str(e)[:80])
            await asyncio.sleep(gap)

    async def recheck_loop(self, notify_fn: Optional[Callable] = None):
        """Continuous phone recheck loop for this engine."""
        await asyncio.sleep(60 + self.engine_id * 15)
        while self._running:
            await asyncio.sleep(120)
            try:
                await self.phone_recheck_pass(notify_fn=notify_fn)
            except Exception as e:
                log.exception("[ENGINE %d] Phone recheck pass failed: %s", self.engine_id, e)
