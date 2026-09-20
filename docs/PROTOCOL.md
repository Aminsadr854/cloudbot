# Cloudbot Phone Probe Protocol Specification

This document provides the definitive specification of the communication protocol between the Cloudbot scanner coordination backend and remote mobile probe handsets (Android devices measuring Cloudflare edge connectivity from within Iranian cellular carrier networks).

---

## 1. Architectural Overview

### 1.1 Components and Topology

```
+-------------------------------------------------------------------------+
|                               Iran Relay                                |
|  [nginx TLS Termination]                                                |
|       |                                                                 |
|       +--> reverse proxy (127.0.0.1:9600)                               |
|       |                                                                 |
|  [probe_srv.py] (optional TCP/SSH banner sink on diagnostic ports)      |
+-------^-----------------------------------------------------------------+
        |
        | Public HTTPS (Port 443 / PROBE_BASE)
        |
+-------+-----------------------------+
|                                     |
| Handset A (MCI)             Handset B (Irancell)
| Android Probe Client        Android Probe Client
+-------------------------------------+
        |
        | Direct probes to Cloudflare edge IPs & Relay Control IP
        v
+-------------------------------------------------------------------------+
|                       Target Candidate Endpoints                        |
|  - Cloudflare Edge IPs (Port 443: TCP, TLS, SNI, HTTP /cdn-cgi/trace)   |
|  - Control Probe Reference IP (Iran Relay status host)                  |
+-------------------------------------------------------------------------+
```

1. **Bot Host Backend (`probeapi.py` on 127.0.0.1:9600):**
   - An asynchronous HTTP service powered by `aiohttp.web`.
   - Exposes REST endpoints to issue candidate IP shortlists and ingest handset measurement reports.
   - Communicates with SQLite storage (`store.py`) to manage per-engine candidate queues and device states.
2. **Iran Relay (`nginx` Reverse Proxy):**
   - Handsets inside Iran never connect directly to the bot host in Europe. Handset traffic to foreign IP ranges is actively shaped and blocked by Iranian deep packet inspection (DPI).
   - Handsets connect exclusively to an existing Iran relay server running `nginx`, which terminates TLS on `PROBE_BASE` (e.g. `https://status.example.com`) and forwards `/probe/*` requests to `probeapi.py`.
3. **Android Handset Probes:**
   - Dedicated handsets equipped with SIM cards from distinct national carriers (e.g. MCI, MTN Irancell, Rightel).
   - Wake up periodically or on notification, poll `probeapi.py` for candidate IP addresses, measure reachability/latency/jitter across cellular data, and submit structured report telemetry.
4. **Diagnostic Sinks (`probe_srv.py`, `probe_cli.py`, `probe_cli2.py`):**
   - Auxiliary TCP raw sockets used for transport diagnostic analysis (SSH banner emulation, client-first vs server-first banner exchanges, bandwidth throttling measurements). They do not participate in the REST candidate polling workflow.

### 1.2 Authentication and Security Model

- **Shared Token Authentication:**
  - Handset requests authenticate using a shared secret token managed in `store.py` (`st.probe_token()`).
  - The token is transmitted either via the HTTP header `X-Probe-Token: <token>` (preferred) or query parameter `?token=<token>`.
  - The token serves as an endpoint access control mechanism and device identifier rather than a cryptographic secret. A compromised token only allows submitting fabricated measurements; it cannot modify bot configuration, access provider API credentials, or manipulate Cloudflare DNS.
- **Transport Security:**
  - All communication between mobile handsets and the relay is encrypted using TLS over HTTPS (port 443).

---

## 2. Protocol v1 Specification (Current Implementation)

### 2.1 Critical Architectural Finding: `engine_id` Handling

> [!IMPORTANT]
> **API vs Client `engine_id` Discrepancy:**
> In the current server implementation (`probeapi.py`), `engine_id` is emitted in the JSON responses of `/probe/candidates`, `/probe/report`, and `/probe/ping`. The server can also parse `engine_id` if provided in query parameters (`?engine=`) or request JSON bodies (`body["engine_id"]`).
>
> **HOWEVER, legacy v1 mobile probe clients (handsets) do NOT send `engine_id` in their requests.**
> Because v1 handsets omit `engine_id`, the backend relies on stateful heuristic multiplexing:
> 1. In `GET /probe/candidates`: the backend calls `st.active_probe_engine(device, operator)` to select whichever engine currently has the oldest uncompleted candidate delivery.
> 2. In `POST /probe/report`: because the incoming JSON body lacks `engine_id`, the backend inspects the candidate IPs inside the report and searches for an IP intersection (`rep_ips & cand_ips`) across Engines 1, 2, and 3. If an intersection is found, it attributes the report to that engine; otherwise, it falls back to `active_probe_engine()`.

---

### 2.2 Endpoints

#### 2.2.1 `GET /probe/health`
Checks API daemon liveness.

- **Authentication:** None.
- **Query Parameters:** None.
- **Response `200 OK`:**
  ```json
  {
    "ok": true,
    "ts": 1726870000
  }
  ```

---

#### 2.2.2 `GET /probe/ping`
Lightweight heartbeat to report device presence, network type, and determine if an immediate test run is required.

- **Authentication:** Required (`X-Probe-Token` or `?token=`).
- **Query Parameters:**
  - `device` (string, max 64 chars): Unique device identifier (e.g. `android-mci-01`).
  - `operator` (string, max 48 chars): Carrier network name (e.g. `MCI`, `Irancell`).
  - `net` (string, max 16 chars): Network connection type (e.g. `cellular`, `wifi`).
  - `app` (string, max 16 chars): Client application build version (e.g. `1.2.0`).
  - `engine` (integer, optional): Explicit scanner engine ID (1, 2, or 3).
- **Server Processing:**
  - Invokes `st.touch_device(device, operator, net, app)` to record online status and metadata.
  - Resolves target engine via `engine` param or `st.active_probe_engine()`.
  - Calculates `run_now = True` if:
    1. The candidate set for the engine is non-empty, AND
    2. The domain SNI changed since the last device report (`stale_test`), OR
    3. A new candidate shortlist was generated since the last report (`old_round`), OR
    4. The device has never measured the current candidate shortlist.
- **Response `200 OK`:**
  ```json
  {
    "ok": true,
    "engine_id": 1,
    "interval_hours": 12,
    "run_now": true
  }
  ```

---

#### 2.2.3 `GET /probe/candidates`
Fetches candidate IP addresses for the handset to measure.

- **Authentication:** Required (`X-Probe-Token` or `?token=`).
- **Query Parameters:** Same as `/probe/ping` (`device`, `operator`, `net`, `app`, `engine`).
- **Server Processing:**
  - Invokes `st.touch_device()`.
  - Determines `engine_id` (explicit query parameter or `st.active_probe_engine()`).
  - Records delivery timestamp via `st.record_candidate_delivery(engine_id, device, operator)`.
  - Retrieves candidate shortlist from `store.py` (`ips`) and injects control reference IPs (`controls`) into the list.
  - Retrieves target domain Host and SNI via `st.get_engine_targets(engine_id)`.
- **Response `200 OK`:**
  ```json
  {
    "ts": 1726870000,
    "engine_id": 1,
    "ips": [
      "104.16.1.10",
      "104.16.1.11",
      "93.184.216.34"
    ],
    "interval_hours": 12,
    "port": 443,
    "rounds": 4,
    "timeout_ms": 4000,
    "host": "speed.cloudflare.com",
    "sni": "cdn.example.com",
    "sni_alt": "speed.cloudflare.com"
  }
  ```
- **Field Definitions:**
  - `ts`: Unix timestamp when the candidate shortlist was compiled by the scanner engine.
  - `engine_id`: Assigned engine ID (1, 2, or 3).
  - `ips`: List of IPv4 addresses to probe (combines Cloudflare candidates + control reference addresses).
  - `port`: Destination TCP port for measurement (typically 443).
  - `rounds`: Repetitions per candidate address to calculate packet loss and jitter (default: 4).
  - `timeout_ms`: Socket timeout in milliseconds for each individual probe attempt (default: 4000).
  - `host`: HTTP `Host` header sent during TLS/HTTP validation.
  - `sni`: Primary TLS Server Name Indication used in ClientHello.
  - `sni_alt`: Fallback SNI used when primary SNI fails, to detect whether filtering is IP-based or SNI-based.

---

#### 2.2.4 `POST /probe/report`
Submits measurement results from a completed test pass.

- **Authentication:** Required (`X-Probe-Token` or `?token=`).
- **Payload Limits:** Maximum request size: 64 KB (`MAX_BODY`). Maximum results array length: 60 entries (`MAX_RESULTS`).
- **Request Body JSON:**
  ```json
  {
    "device": "android-mci-01",
    "operator": "MCI",
    "net": "cellular",
    "app": "1.2.0",
    "engine_id": 1,
    "results": [
      {
        "ip": "104.16.1.10",
        "ok": true,
        "rtt_ms": 94.2,
        "loss": 0.0,
        "stage": "ok"
      },
      {
        "ip": "104.16.1.11",
        "ok": false,
        "rtt_ms": null,
        "loss": 1.0,
        "stage": "tcp"
      },
      {
        "ip": "93.184.216.34",
        "ok": true,
        "rtt_ms": 35.1,
        "loss": 0.0,
        "stage": "ok"
      }
    ]
  }
  ```
- **Result Item Attributes:**
  - `ip` (string, required): Probed IPv4 address.
  - `ok` (boolean, required): Whether the address is fully usable for user traffic.
  - `rtt_ms` (float/null): Average round-trip time in milliseconds (excluding timeouts).
  - `loss` (float/null): Loss ratio between `0.0` and `1.0`.
  - `stage` (string, optional): Diagnostic point of failure:
    - `"ok"`: Handshake, TLS, and HTTP response succeeded.
    - `"tcp"`: TCP SYN was dropped, timed out, or reset; never reached port.
    - `"tls"`: TCP connected, but TLS ClientHello/Handshake was intercepted or RST injected.
    - `"sni"`: Connection failed under target `sni`, but succeeded under `sni_alt` (confirms domain/SNI filtering).
- **Server Attribution Logic:**
  1. If `engine_id` is present in body or query param, uses it.
  2. If absent, extracts all `ip` entries in `results` and checks against candidate shortlists of engines 1, 2, 3:
     `rep_ips & cand_ips`
  3. If no match, falls back to `st.active_probe_engine(device, operator)`.
- **Response `200 OK`:**
  ```json
  {
    "ok": true,
    "accepted": 3,
    "engine_id": 1
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Missing `device`, missing `results`, or invalid JSON.
  - `401 Unauthorized`: Missing or invalid probe token.
  - `413 Payload Too Large`: Body exceeds 64 KB.

---

### 2.3 Consensus, Trust, and Voting Model

1. **Cellular Requirement:**
   - Handset reports measured over Wi-Fi (`net == "wifi"`) are strictly set aside and never participate in candidate selection or consensus.
2. **Control Address Grounding (`_report_trusted`):**
   - Alongside Cloudflare candidates, the backend injects the Iran Relay IP as a control address.
   - If a handset reports `ok=False` for the control IP, the entire round is deemed untrusted (`_report_trusted` returns `False`): the handset's own radio connection was down, so candidate failures describe the handset, not Cloudflare.
3. **2/2 Carrier Consensus:**
   - Candidate promotion requires agreement across distinct carrier networks (e.g. MCI + Irancell).
   - An address is only verified if both mobile carriers report it operational (`ok=True`).
   - If any carrier reports failure on a trusted round, the address is penalized and recorded in `blocked_ip_failures`.

---

## 3. Protocol v2 Specification (Target Architecture)

### 3.1 Architectural Motivations

1. **Eliminate Heuristic Engine Attribution:** Handsets must explicitly echo `engine_id` in all requests so the backend never relies on IP set intersection.
2. **Deterministic Candidate Set Matching:** Prevent race conditions where a scan finishes while a phone is testing. Handsets must echo `candidate_hash` and `shortlist_ts`.
3. **Multi-Engine Scheduling Support:** Allow modern handsets to discover whether multiple engines have pending shortlists, enabling a handset to test Engine 1, then immediately test Engine 2.
4. **Fine-Grained Telemetry:** Add explicit timing stages (`tcp_ms`, `tls_ms`, `ttfb_ms`) to distinguish between TLS certificate tampering and TCP transport latency.

---

### 3.2 v2 Endpoints & Schema Enhancements

#### 3.2.1 `GET /probe/v2/ping`
- **Request Headers:**
  - `X-Probe-Token: <token>`
  - `X-Probe-Protocol: 2`
- **Query Parameters:**
  - `device`: Unique device ID.
  - `operator`: Carrier name.
  - `net`: Network connection type.
  - `app`: Client app build string.
- **Response `200 OK`:**
  ```json
  {
    "ok": true,
    "protocol_version": 2,
    "pending_engines": [
      {
        "engine_id": 1,
        "candidate_hash": "a1b2c3d4e5f6",
        "shortlist_ts": 1726870000,
        "run_now": true
      },
      {
        "engine_id": 2,
        "candidate_hash": "f6e5d4c3b2a1",
        "shortlist_ts": 1726870300,
        "run_now": false
      }
    ],
    "interval_hours": 12
  }
  ```

---

#### 3.2.2 `GET /probe/v2/candidates`
- **Query Parameters:**
  - `engine` (integer, required in v2): Explicit engine being requested.
  - `device`, `operator`, `net`, `app`.
- **Response `200 OK`:**
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
    "controls": [
      "93.184.216.34"
    ],
    "candidates": [
      "104.16.1.10",
      "104.16.1.11"
    ],
    "probe_config": {
      "rounds": 4,
      "timeout_ms": 4000
    }
  }
  ```

---

#### 3.2.3 `POST /probe/v2/report`
- **Request Body JSON:**
  ```json
  {
    "protocol_version": 2,
    "device": "android-mci-01",
    "operator": "MCI",
    "net": "cellular",
    "app": "2.0.0",
    "engine_id": 1,
    "candidate_hash": "a1b2c3d4e5f6",
    "shortlist_ts": 1726870000,
    "results": [
      {
        "ip": "104.16.1.10",
        "ok": true,
        "tcp_ms": 42.1,
        "tls_ms": 52.1,
        "ttfb_ms": 94.2,
        "loss": 0.0,
        "stage": "ok"
      },
      {
        "ip": "104.16.1.11",
        "ok": false,
        "tcp_ms": null,
        "tls_ms": null,
        "ttfb_ms": null,
        "loss": 1.0,
        "stage": "tcp"
      },
      {
        "ip": "93.184.216.34",
        "ok": true,
        "is_control": true,
        "tcp_ms": 15.0,
        "tls_ms": 20.1,
        "ttfb_ms": 35.1,
        "loss": 0.0,
        "stage": "ok"
      }
    ]
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "ok": true,
    "accepted": 3,
    "engine_id": 1,
    "candidate_hash": "a1b2c3d4e5f6",
    "state": "ACCEPTED"
  }
  ```

---

## 4. Backward Compatibility & Coexistence Strategy

1. **Dual-Stack Routing:**
   - Existing endpoints (`/probe/ping`, `/probe/candidates`, `/probe/report`) remain completely functional for legacy v1 handsets.
   - New v2 endpoints (`/probe/v2/*`) serve upgraded v2 handsets.
2. **Seamless Fallback:**
   - When a v1 handset submits a report without `candidate_hash` or `engine_id`, the backend executes the v1 heuristic matching logic (`rep_ips & cand_ips`).
   - When a v2 handset connects, the server processes deterministic attribution with zero heuristic guessing.
3. **Safety Guarantee:**
   - Both v1 and v2 reports feed into the same backend Store (`store.py:save_device_report` and `record_candidate_report`), ensuring consensus evaluation functions uniformly regardless of client app version.
