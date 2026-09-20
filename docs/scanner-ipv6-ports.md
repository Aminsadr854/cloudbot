# Design Specification: IPv6 Ranges and Alternative TLS Ports (Task D4)

## 1. Overview

Currently, the scanner is restricted to IPv4 (`/ips-v4`) and standard HTTPS port `443`.
Cloudflare operates on both IPv4 and IPv6, and terminates TLS on six distinct ports:
`443, 2053, 2083, 2087, 2096, 8443`.

Scanning IPv6 and alternative ports expands the search space for clean endpoints during aggressive censorship rounds when IPv4 `/24` subnets and port 443 undergo heavy SNI filtering or throttling.

---

## 2. Part A: IPv6 Scanning Design

### Cloudflare IPv6 Topology
Cloudflare announces 7 IPv6 CIDR blocks (e.g., `2606:4700::/32`, `2a06:98c0::/29`, `2803:f800::/32`).
Because IPv6 address spaces are immense (a single `/32` contains $2^{96}$ addresses), decomposing by host offsets as done in IPv4 `/24` is impossible.

### Candidate Sampling for IPv6
- **Sampling Hierarchy**: Cloudflare edge anycast addresses typically terminate on `/64` or `/48` boundaries.
- The candidate generator will sample subnets at the `/64` level, selecting pseudo-random host identifiers or known anycast suffixes (such as `::1`, `::100`, or uniform random lower 64 bits).
- Range fetching: Add `CF_V6_URL = "https://www.cloudflare.com/ips-v6"`, cached on the bot host alongside IPv4 ranges.

### Socket & Transport Changes
- In `cf_scan.py`:
  - Socket calls must detect address family:
    ```python
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    ```
  - HTTP Host headers and TLS SNI: IPv6 addresses must be bracketed in URL and Host headers (e.g. `[2606:4700::1]:443`).
- **Relay Constraint**: Many Iran VPS providers provide incomplete or unrouted IPv6 connectivity. The scanner must verify local IPv6 egress before launching IPv6 probes; if IPv6 egress is absent, IPv6 scanning must be skipped automatically.

### DNS & Cloudflare Client Changes
- Cloudflare DNS requires **`AAAA`** records for IPv6 (not `A` records).
- `Cloudflare` API client in `scanner_engine.py` must support:
  - `find_aaaa_record(zone_id, name)`
  - `create_aaaa(zone_id, name, content)`
  - `update_aaaa(zone_id, rec, content)`

---

## 3. Part B: Alternative TLS Ports Design

Cloudflare's edge accepts HTTP/TLS on the following ports:
- **Default**: `443`
- **Alternative HTTPS**: `2053`, `2083`, `2087`, `2096`, `8443`

### CLI Flag Specification
- Change `--port` in `cf_scan.py` to accept a comma-separated list:
  ```bash
  --ports 443,2053,2083,2087,2096,8443
  ```
  Default: `443`.
- In `cfscanner._build_scan_args`, add keyword parameter `ports: list[int] | None = None`.

### Staged Probing Architecture
Testing all 6 ports across thousands of candidates in Stage 1 would multiply traffic by 6x.
Instead, a **staged port probe pipeline** is required:
1. **Stage 1 (TCP)**: Probes candidates on standard port `443`.
2. **Stage 2 (TLS / Edge)**: Responsive IPs are probed on port `443`.
3. **Stage 3 (Multi-Port Stability Check)**: For finalists reaching the stability stage, probe across the configured `--ports` list.
4. Each result object represents an `(ip, port)` endpoint tuple:
   ```json
   {
     "ip": "104.16.12.34",
     "port": 8443,
     "rtt": 42.5,
     "jitter": 2.1,
     "loss": 0.0,
     "score": 50.9
   }
   ```

---

## 4. Comparing and Ranking Across Ports

### Ranking Formulation
The canonical score formula $S = \text{rtt} + 4 \times \text{jitter} + 50 \times \text{loss}$ is port-agnostic and measures path quality directly.
However, non-standard ports face operational penalties:
1. **Firewall / Captive Portal Blocks**: Hotel, corporate, and cellular networks frequently block non-443 outgoing TCP traffic.
2. **CDN Proxy Compatibility**: Some client protocols require explicit port handling.

### Port Bias / Penalty
To reflect this operational risk, apply an explicit port penalty to non-443 endpoints during scoring:
$$S_{\text{effective}} = S + \Delta P$$
- $\Delta P = 0$ for port `443`.
- $\Delta P = +15.0$ for alternative ports (`2053, 2083, 2087, 2096, 8443`).

An alternative port is only chosen if its path latency or stability is substantially better than port 443 on the same or neighboring IP.

---

## 5. Storage Schema & Phone Integration

### Can Store Schema Represent Port Alongside Address?
**Yes**:
- In `store.py`, candidate records are JSON dictionaries. Adding `"port": int` (defaulting to `443`) is backward-compatible with existing data.
- Unique keying: In pools and shortlists, endpoints must be keyed by `(ip, port)` (or `f"{ip}:{port}"` / `f"[{ip}]:{port}"`) rather than `ip` alone.

### Can Phone-Testing Side Represent Ports?
**Yes, with client protocol considerations**:
- **Mobile Handset Probes**: The phone test suite connects via client config (V2Ray / Xray / Shadowsocks). These protocols natively support custom destination ports in the server configuration.
- **DNS Limitation**: DNS `A` and `AAAA` records do not contain port numbers. Repointing a domain on Cloudflare does not alter the client connection port.
- **Delivery**: If an alternative port (e.g. `8443`) is selected, the bot cannot merely update the DNS A record; it must update the client subscription profile distributed to users so client apps connect to `fqdn:8443`.

---

## 6. Required Modifications Summary

| Component | Target File | Modifications Needed |
| :--- | :--- | :--- |
| **CLI & Sampling** | `cf_scan.py` | Add `--ports` list parsing; add IPv6 range loader and `/64` random subnet sampler; socket `AF_INET6` family switching. |
| **Scanner Caller** | `cfscanner.py` | Pass `--ports` argument; parse `(ip, port)` candidate records; support bracketed IPv6 strings. |
| **Engine & DNS** | `scanner_engine.py` | Key pools by `(ip, port)`; add `AAAA` record operations to Cloudflare API client; support client port updates. |
| **Store** | `store.py` | Update `scan_pool` and `set_scan_candidates` to index by `(ip, port)`; add migration for legacy entries defaulting to port 443. |
| **Phone Probes** | Handset apps | Parse `port` parameter from test payload and configure test proxy connection accordingly. |
