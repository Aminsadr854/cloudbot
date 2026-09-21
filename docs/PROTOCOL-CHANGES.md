# Required Server-Side Changes for Phone Probe Protocol v2

This document details the exact modifications required on the Cloudbot server backend to implement the v2 protocol specified in [`docs/PROTOCOL.md`](file:///root/cloudbot/docs/PROTOCOL.md).

> [!NOTE]
> This is an architectural and design specification. No backend code modifications have been made yet, in compliance with the design-first requirement.

---

## 1. Executive Summary of Server Changes

The primary limitation of the v1 protocol is that mobile handsets never transmit `engine_id` or `candidate_hash`. The server must guess which engine a report belongs to by computing IP intersections against current engine shortlists.

Upgrading to Protocol v2 requires server-side changes across four components:
1. **API Router & Handlers (`probeapi.py`):** Add versioned v2 endpoints (`/probe/v2/candidates`, `/probe/v2/report`, `/probe/v2/ping`), enforce explicit `engine_id` roundtripping, and separate candidate IPs from control reference addresses in responses.
2. **State Store (`store.py`):** Record client protocol versions in the `devices` table, validate incoming reports against candidate set hashes, and persist granular stage timings (`tcp_ms`, `tls_ms`, `ttfb_ms`).
3. **Delivery Coordinator (`scanner_engine.py`):** Support multi-engine awareness so a single handset poll can discover pending shortlists across multiple engines.
4. **Telegram UI (`bot.py`):** Surface client protocol version in the device status dashboard.

---

## 2. Endpoint-by-Endpoint Server Specifications

### 2.1 `GET /probe/v2/ping`

- **File:** `probeapi.py`
- **Current Limitation:** In v1, `/probe/ping` only resolves a single `engine_id` (via `st.active_probe_engine()`). If Engine 1 and Engine 2 both have pending candidate sets, the handset only learns about one of them.
- **Required Changes:**
  1. Add async handler `ping_v2(request)`.
  2. Iterate across all registered engines (1, 2, 3) and evaluate `run_now` criteria for each:
     ```python
     pending = []
     for eid in (1, 2, 3):
         cand = st.scan_candidates(engine_id=eid)
         # evaluate stale_test, old_round, and unmeasured candidates
         pending.append({
             "engine_id": eid,
             "candidate_hash": cand.get("candidate_hash", ""),
             "shortlist_ts": cand.get("ts", 0),
             "run_now": run_now
         })
     ```
  3. Return the array `pending_engines`.
  4. Record `proto=2` in device metadata via `st.touch_device()`.

---

### 2.2 `GET /probe/v2/candidates`

- **File:** `probeapi.py`
- **Current Limitation:** In v1, candidate IPs and control reference addresses are merged into a single `ips` array. Handsets have no explicit contract distinguishing reference addresses from test candidates, and must poll without specifying an engine unless they know internal engine IDs.
- **Required Changes:**
  1. Add async handler `candidates_v2(request)`.
  2. Require an explicit `engine` query parameter (`?engine=1`, `?engine=2`, or `?engine=3`). If omitted, return `400 Bad Request` with an error message: `"engine parameter required in protocol v2"`.
  3. Emit structured response separating candidates from controls:
     ```json
     {
       "protocol_version": 2,
       "engine_id": 1,
       "candidate_hash": "a1b2c3d4e5f6",
       "shortlist_ts": 1726870000,
       "expires_at": 1726880800,
       "targets": {
         "port": 443,
         "host": "speed.cloudflare.com",
         "sni": "cdn.example.com",
         "sni_alt": "speed.cloudflare.com",
         "path": "/cdn-cgi/trace"
       },
       "controls": ["93.184.216.34"],
       "candidates": ["104.16.1.10", "104.16.1.11"],
       "probe_config": {
         "rounds": 4,
         "timeout_ms": 4000
       }
     }
     ```
  4. Include `candidate_hash` directly in the payload so the handset can echo it in its report.

---

### 2.3 `POST /probe/v2/report`

- **File:** `probeapi.py`
- **Current Limitation:** In v1, the backend performs heuristic IP set intersection (`rep_ips & cand_ips`) across all engines because the handset body omits `engine_id`. If a candidate IP appears in multiple engines or all reported addresses fail, attribution is ambiguous.
- **Required Changes:**
  1. Add async handler `report_v2(request)`.
  2. **Strict Validation Pipeline:**
     - Validate `X-Probe-Token`: return `401 Unauthorized` with `{"ok": false, "reason": "unauthorized"}` if invalid.
     - Validate payload size: return `413 Payload Too Large` with `{"ok": false, "reason": "payload_too_large"}` if > 64 KB or > 60 items.
     - Validate `engine_id`: return `400 Bad Request` with `{"ok": false, "reason": "invalid_engine"}` if missing or not in `[1, 3]`.
     - Validate `candidate_hash`: return `400 Bad Request` with `{"ok": false, "reason": "invalid_hash"}` if missing or malformed.
     - Validate network interface: return `422 Unprocessable Entity` with `{"ok": false, "reason": "non_cellular"}` if `net != "cellular"`.
  3. **Candidate Hash & Shortlist Freshness Check:**
     - Retrieve active delivery state: `state = st.get_delivery_state(engine_id)`.
     - If candidate set has expired (`time > cand_ts + SHORTLIST_DELIVERY_TTL`) or engine has advanced to a new shortlist: return `409 Conflict` with `{"ok": false, "reason": "stale_shortlist"}`.
  4. **Full List & Hash Matching:**
     - Recompute hash: `rep_hash = st.candidate_set_hash(reported_ips, controls)`.
     - If `rep_hash != state["candidate_set_hash"]`: return `422 Unprocessable Entity` with `{"ok": false, "reason": "hash_mismatch"}`.
  5. **Idempotency Guard:**
     - Check if device report with identical `candidate_hash` was already processed:
       ```python
       dev_state = state["devices"].get(device, {})
       if dev_state.get("status") == "COMPLETE" and dev_state.get("report_candidate_set_hash") == rep_hash:
           return web.json_response({"ok": true, "reason": "already_recorded", "engine_id": engine_id})
       ```
  6. **Successful Acceptance:**
     - Ingest granular timings (`tcp_ms`, `tls_ms`, `ttfb_ms`).
     - Mark handset `COMPLETE` for that engine and reset `fetch_count = 0`.
     - Return `200 OK` with `{"ok": true, "reason": "accepted", "engine_id": engine_id, "candidate_hash": rep_hash}`.

---

## 3. Storage and Database Layer Changes (`store.py`)

### 3.1 Device Tracking Table Schema Update

The `devices` table currently stores:
```sql
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT,
    last_seen INTEGER,
    operator TEXT,
    net TEXT,
    app TEXT
);
```

**Proposed Migration:**
Add a `proto` column to track the protocol capability of each connected handset:
```sql
ALTER TABLE devices ADD COLUMN proto INTEGER DEFAULT 1;
```
Update `touch_device(dev, op, net, app, proto=1)` to persist this version.

---

### 3.2 Candidate Metadata Enhancement

In `set_scan_candidates()`, ensure `candidate_hash` is always stored at top level of the JSON payload for all engines:
```python
payload = {
    "ts": int(time.time()),
    "engine_id": engine_id,
    "candidate_hash": cand_hash,
    "ips": ips,
    "metrics": metrics,
    "controls": controls
}
```

---

### 3.3 Starved Handset Detection (`fetch_count`)

In `record_candidate_delivery()`, increment a persistent counter tracking consecutive shortlist deliveries:
```python
dev_state["fetch_count"] = dev_state.get("fetch_count", 0) + 1
```
When a valid report completes in `record_candidate_report()`, reset `dev_state["fetch_count"] = 0`.
If `fetch_count >= 3`, surface a warning flag in `/probe/v2/ping` and mark the device on Telegram.

---

## 4. Telegram UI Changes (`bot.py`)

In [`bot.py:3880-3890`](file:///root/cloudbot/bot.py#L3880-L3890) (`cb_scan_verified` handler):
Display protocol version badge next to each connected device:
- `v1` handsets: `📱 MCI (v1.2.0 · Proto 1)`
- `v2` handsets: `📱 MCI (v2.0.0 · Proto 2)`

This gives the operator immediate visual confirmation when handsets update to the new protocol.

---

## 5. Rollout and Migration Plan

```
Phase 1: Deploy Server Changes (Dual-Stack)
  - Deploy updated probeapi.py and store.py supporting both v1 and v2.
  - Existing v1 handsets continue reporting seamlessly via /probe/*.

Phase 2: Distribute v2 Android Client
  - Distribute updated APK targeting /probe/v2/* endpoints.
  - v2 handsets transition to deterministic engine attribution.

Phase 3: Deprecate v1 Heuristics
  - Once all registered devices report with Proto 2, log warnings on legacy v1 calls.
  - Retire IP set intersection logic after full fleet upgrade.
```
