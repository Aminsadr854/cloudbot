# Technical Debt: bot.py Cloudflare Scanner Call Sites

This document audits the legacy Cloudflare scanner call sites in `bot.py` identified during verification. None of these call sites were updated when the multi-engine architecture (`ScannerEngine`) and Group-A correctness guarantees were introduced.

All four call sites invoke `cfscanner.run_scan()` without passing `engine_id`, implicitly defaulting to `engine_id=1`. This produces severe isolation, concurrency, and safety issues when running alongside the automatic scanning subsystems.

---

## Call Site 1: `_scan_pass` (bot.py:1754–1758)

### What it does today
```python
# bot.py:1750-1759
async def _scan_pass(log):
    cfg = st.cfscan()
    ssh = cfg.get("ssh")
    if not ssh:
        return 0
    results, _tail = await cfscanner.run_scan(
        ssh, st.jump(), log, limit=SCAN_SAMPLE,
        final=PHONE_SHORTLIST, no_speed=True)
    st.pool_add(results)
    return len(results)
```
Invoked by manual bot commands (`/scan_now` or admin test menus) and legacy single-engine background tasks. It runs a candidate sampling pass (defaulting to `engine_id=1`) and adds the results to the pool via `st.pool_add(results)`.

### Which `ScannerEngine` method it duplicates
Duplicates [`ScannerEngine.scan_pass(log_fn)`](file:///root/cloudbot/scanner_engine.py#L445-L463).

### What goes wrong when run concurrently with Engine 1
1. **Remote file collisions**: Both write to `/root/.cf_scan_engine_1.py`, `/root/.cf_ranges_engine_1.txt`, and `/root/cf_bot_scan_engine_1.json`.
2. **Process termination conflict (A7)**: `run_scan` uses `pkill -TERM -f /root/.cf_scan_engine_1.py` on startup and timeout. If Engine 1 is running an automated pass, triggering a manual scan immediately kills Engine 1's scanner process mid-execution.
3. **Stale result corruption (A8)**: Whichever scan writes to `/root/cf_bot_scan_engine_1.json` last will overwrite the other. If timestamps do not align with `scan_start_time`, `StaleResultError` is raised in the calling task.
4. **Pool cross-contamination**: Candidates found by the manual scan are added to Engine 1's pool without Engine 1's status tracking or locking.

### Which A-group safety guarantees it bypasses
- **A2 (Per-engine script isolation)**: Shares Engine 1's remote script and files instead of using an isolated execution namespace.
- **A7 (Remote timeouts & clean termination)**: Kills Engine 1's remote processes.
- **A8 (Freshness & engine ID validation)**: Can trigger or suffer from race conditions in atomic result validation.
- **D2 Step 1 (Exclude blocked IPs)**: Does not pass `exclude=list(st.blocked_ips())`, meaning it repeatedly spends bandwidth scanning known-bad/blocked IPs.

### Options for fixing & tradeoffs
- **Option 1: Route through `ScannerEngine.scan_pass`**: Call `await engine1.scan_pass(log)`.
  - *Pros*: Preserves single lock hierarchy, updates engine status properly, passes blocked IPs.
  - *Cons*: If Engine 1 is currently in the middle of a scan pass or window close, the manual scan must wait for `self.lock` (up to 15 minutes).
- **Option 2: Dedicated engine ID for manual scans (`engine_id=0` or `engine_id=99`)**: Pass a reserved `engine_id` to `cfscanner.run_scan`.
  - *Pros*: Isolated remote script and output file; `pkill` never interferes with automated engines; can run concurrently without file conflicts.
  - *Cons*: Its results do not belong to an engine pool unless explicitly merged; increases remote server load if run concurrently.
- **Option 3: Lock-check refusal**: Refuse to execute if `engine1.lock.locked()`, reporting back to Telegram that Engine 1 is busy.
  - *Pros*: Simple to implement, prevents collisions.
  - *Cons*: Poor user experience for bot administrators.

---

## Call Site 2: `_close_window` (bot.py:1862–1868)

### What it does today
```python
# bot.py:1856-1868
    entries.sort(key=cfscanner.score)
    top = [e["ip"] for e in entries[:PHONE_SHORTLIST]]
    await log(f"پایان پنجره: {len(entries)} آدرس در {pool.get('passes')} پاس — "
              f"{len(top)} تای برتر دوباره سنجیده می‌شوند")

    ssh = cfg.get("ssh")
    results, _tail = await cfscanner.run_scan(ssh, st.jump(), log, only=top,
                                              final=PHONE_SHORTLIST)
    if not results:
        # The re-check found nothing alive; the pool's own numbers still stand.
        results = entries[:PHONE_SHORTLIST]
    results.sort(key=cfscanner.score)
```
Followed immediately by `st.set_scan_candidates(shortlist, ...)` and `st.pool_reset()`.

### Which `ScannerEngine` method it duplicates
Duplicates [`ScannerEngine.close_window(log_fn)`](file:///root/cloudbot/scanner_engine.py#L464-L508).

### What goes wrong when run concurrently with Engine 1
1. **Silent state destruction (Critical Severity)**: Calls `st.pool_reset()` without holding Engine 1's lock. A manual scan can therefore wipe a scan pool that has been accumulating for hours, mid-window, with no warning to anyone. That is silent destruction of work, not just a collision.
2. **Remote file and process collisions**: Runs as `engine_id=1`, colliding with Engine 1's active scan files and killing running probes via `pkill`.
3. **Candidate overwrites**: Overwrites `st.set_scan_candidates` for Engine 1 with an unsynchronized shortlist, breaking multi-engine phone delivery coordination.

### Which A-group safety guarantees it bypasses
- **A2 / A7 / A8 (Script and result isolation)**: Collides on Engine 1's filesystem and process space.
- **A4 (Keep current IP on missing measurement)**: If `results` is empty, it uses `entries[:PHONE_SHORTLIST]`, but downstream code in `bot.py:1880–1920` updates DNS without verifying whether the existing live IP was re-measured.
- **A5 & A6 (DNS verification and rollback)**: If `bot.py` proceeds to repoint the domain in lines 1880–1920, it calls `cf.update_a(...)` directly with zero DNS resolution confirmation and zero rollback logic if the new IP is unresponsive.

### Options for fixing & tradeoffs
- **Option 1: Route through `ScannerEngine.close_window`**: Call `await engine1.close_window(log)`.
  - *Pros*: Completely removes duplicated logic; reuses phone delivery coordinator and per-engine pool state safely.
  - *Cons*: Blocks on Engine 1 lock.
- **Option 2: Dedicated engine ID**:
  - *Pros*: Fixes remote script collision.
  - *Cons*: Does NOT fix state destruction (`st.pool_reset()` and `st.set_scan_candidates` still corrupt Engine 1 store state).
- **Option 3: Lock-check refusal**: Refuse if Engine 1 is active.
  - *Pros*: Prevents simultaneous window closing.
  - *Cons*: Does not resolve the downstream lack of A5/A6 DNS safety checks.

---

## Call Site 3: `_heal_target` (bot.py:3012–3018)

### What it does today
```python
# bot.py:3006-3019
async def _heal_target(t, log_fn):
    """A CDN-fronted config went bad: find a fresh clean IP and repoint it."""
    scan = st.cfscan()
    ssh = scan.get("ssh")
    if not (ssh and st.cf_token() and t.get("fqdn")):
        return None
    results, _tail = await cfscanner.run_scan(ssh, st.jump(), log_fn,
                                              per_24=1, rounds=8, final=10)
    if not results:
        return None
    best = results[0]
    await _apply_ip(t["fqdn"], best["ip"])
    return best
```
Triggered by the watchdog probe loop (`_do_watch`) when a CDN target is detected as down. It runs an emergency mini-scan (`rounds=8, final=10`), takes the first result, and immediately points Cloudflare DNS to that IP via `_apply_ip()`.

### Which `ScannerEngine` method it duplicates
Does not directly duplicate a `ScannerEngine` method, but replaces the entire decision and update pipeline of [`phone_recheck_pass`](file:///root/cloudbot/scanner_engine.py#L562-L701).

### What goes wrong when run concurrently with Engine 1
1. **Critical remote kill**: If Engine 1 is running its regular scheduled scan, watchdog triggering `_heal_target` will invoke `run_scan(..., engine_id=1)` which executes `pkill -TERM -f /root/.cf_scan_engine_1.py`, abruptly terminating Engine 1's scan.
2. **File and timestamp races**: Both read and write `/root/cf_bot_scan_engine_1.json`, resulting in corrupt reads or `StaleResultError`.
3. **Broken healing failure (Critical Severity)**: Call site 3 is on the watchdog healing path, which by definition runs when something is already broken. It repoints a production domain with none of the A5 prevalidation, DNS confirmation, or A6 rollback. The worst-case is: a config goes down, the watchdog "heals" it onto a filtered address, and now it is down in a way that looks healed.

### Which A-group safety guarantees it bypasses
- **CRITICAL: Bypasses A5 (DNS resolution & propagation confirmation)**: `_apply_ip` blindly modifies Cloudflare DNS and returns. It never verifies that DNS resolves to the new IP or that the new IP responds.
- **CRITICAL: Bypasses A6 (Rollback on failure)**: If Cloudflare DNS update fails, or if the chosen IP does not resolve properly, `_heal_target` has no rollback mechanism. In contrast, `phone_recheck_pass` restores `previous_live_ip` and deletes orphan records.
- **Bypasses A4 (Current IP retention)**: Does not measure the current live IP or test whether the new candidate beats it by `min_gain`.
- **Bypasses A2, A7, A8 isolation**: Reuses Engine 1's remote resources.

### Options for fixing & tradeoffs
- **Option 1: Route through `phone_recheck_pass` or shared DNS updater**: Expose a verified IP repoint helper (`cf_safe_update_ip(fqdn, new_ip)`) that encapsulates A5 DNS verification and A6 rollback.
  - *Pros*: Ensures every DNS modification in the system is safe and protected against blackholes.
  - *Cons*: Requires extracting DNS verification/rollback into a shared function.
- **Option 2: Dedicated engine ID (`engine_id=0` / emergency ID) + shared DNS updater**:
  - *Pros*: Emergency healing scans run without waiting behind Engine 1's lock (watchdog healing must be fast), without remote file or process collisions, and DNS repointing is safely verified and rollback-capable.
  - *Cons*: Consumes concurrent bandwidth on the Iran relay.
- **Option 3: Lock-check refusal**:
  - *Pros*: None.
  - *Cons*: Unacceptable: if Engine 1 is scanning, the watchdog cannot heal a broken customer endpoint for up to 15 minutes.

---

## Call Site 4: `_head_to_head` (bot.py:3688–3693)

### What it does today
```python
# bot.py:3682-3696
    only = ([live_ip] if live_ip else []) + [ip for ip in ips if ip != live_ip]

    async def hlog(t):
        log.info("head-to-head: %s", t)

    try:
        rows, _tail = await cfscanner.run_scan(ssh, st.jump(), hlog, only=only, final=len(only))
    except Exception:
        log.exception("head-to-head measurement failed")
        return None
    measured = {r["ip"]: {k: v for k, v in r.items() if k != "ip"} for r in rows if r.get("ip")}
    st.set("scan_h2h", json.dumps({"key": key, "ts": int(time.time()), "measured": measured}))
```
Performs a head-to-head comparison between the live IP and shortlisted candidates for the legacy single-engine decision pipeline.

### Which `ScannerEngine` method it duplicates
Direct duplicate of [`ScannerEngine._head_to_head`](file:///root/cloudbot/scanner_engine.py#L321-L328).

### What goes wrong when run concurrently with Engine 1
Collides with Engine 1's remote script, output file, and `pkill` cleanup. If Engine 1's automatic `phone_recheck_pass` or `scan_pass` is running, one will clobber the other's output file or abort the other process.

### Which A-group safety guarantees it bypasses
- **A2 / A7 / A8**: Bypasses engine isolation, process safety, and freshness validation.
- **Multi-engine domain routing**: Writes to global key `scan_h2h` rather than engine-specific state, potentially misleading multi-engine decision logic.

### Options for fixing & tradeoffs
- **Option 1: Route through `ScannerEngine._head_to_head`**:
  - *Pros*: Deduplicates code and correctly isolates by engine.
  - *Cons*: Needs an engine instance.
- **Option 2: Dedicated engine ID (`engine_id=0`)**:
  - *Pros*: Allows standalone re-check without touching Engine 1.
  - *Cons*: Maintains duplicate code.

---

## Final Recommendation

The legacy call sites in `bot.py` should be migrated to the multi-engine architecture by deprecating `_scan_pass`, `_close_window`, and `_head_to_head` in `bot.py` and delegating them directly to the corresponding `ScannerEngine` instance, while assigning emergency watchdog scans (`_heal_target`) a dedicated `engine_id=0` with a shared A5/A6 verified-update-and-rollback helper so emergency healing never collides with background engine scans or leaves production domains pointed at unconfirmed IPs. Whatever the migration, call site 3 must go through the same verified-update-and-rollback helper as the engine path, because an emergency is when you need the safety checks most, not least.
