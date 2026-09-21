# Design Specification: Cloudflare IPv6 Scanning (Task D4)

## 1. Overview and Status

This document scopes the requirements, constraints, and architecture for adding Cloudflare IPv6 (`/ips-v6`) scanning to `cloudbot`.

> **Status: DESIGN ONLY / HOLD.**
> Client-side network analysis shows this design is currently blocked by Iranian mobile network constraints (see Section 2). No code will be implemented.

---

## 2. The Blocker: Iranian Mobile Handset IPv6 Connectivity

The clean-IP system requires a two-phone vote: an address identified as fast by the Iran relay is only pointed to production DNS after at least two independent mobile handsets in Iran test and vouch for it via the Telegram bot probe harness.

### Iranian Cellular Realities
- **APN Configuration**: On MCI (Hamrah-e Aval), MTN Irancell, and Rightel, default cellular APN profiles are configured for **IPv4-only** (behind carrier-grade NAT, `100.64.0.0/10`).
- **Dual-Stack Instability**: Even when handsets manually configure dual-stack APNs (`IPv4/IPv6`), international IPv6 routing through TIC (Telecommunication Infrastructure Company) is frequently non-functional, blackholed, or heavily throttled compared to IPv4.
- **Vote Failure**: If handsets cannot establish end-to-end IPv6 connectivity to Cloudflare's edge, every IPv6 candidate will fail handset verification (`ok: false`). Under `choose()` and `phone_recheck_pass`, an unvouched candidate will never be selected for DNS repointing.

**Conclusion**: Until consumer cellular networks in Iran reliably support dual-stack routing to Cloudflare edge IPs, IPv6 deployment to end-users is non-viable.

---

## 3. Bounded Candidate Generation: The C1 Lesson for IPv6

Cloudflare announces 7 IPv6 CIDR blocks:
`2400:cb00::/32`, `2606:4700::/32`, `2803:f800::/32`, `2405:b500::/32`, `2405:8100::/32`, `2a06:98c0::/29`, `2c0f:f248::/32`.

### The Scale Hazard
A single `/32` prefix contains $2^{32} \approx 4.29 \times 10^9$ `/64` subnets. Across all 7 ranges, there are more than **35 billion `/64` subnets**.
Enumerating or shuffling `/64` subnets (as C1 does for 5,956 IPv4 `/24` subnets) would require gigabytes of RAM and terminate the process via OOM.

### Bounded Generator Design ($O(\text{limit})$)
Candidate generation must never materialize subnets. It must generate candidates on the fly:
1. Weight the 7 base CIDRs by their prefix size (e.g. `/29` has $8\times$ the weight of `/32`).
2. For each requested candidate up to `limit`:
   - Pick a CIDR block according to weight.
   - Sample a random 64-bit subnet integer within that CIDR block using Python's `random.getrandbits()`.
   - Append Cloudflare's edge anycast interface identifier (`::1`, `::100`, or low random bits).
   - Format directly into a canonical bracketed IPv6 string: `[2606:4700:xxxx:xxxx::1]`.
3. Running time is strictly $O(\text{limit})$, allocating only the final string list (~50 KB for 1,000 candidates), taking $< 5$ ms.

---

## 4. Relay Egress Detection and Mid-Scan Failures

Many Iranian VPS hosting providers offer servers with IPv6 addresses configured locally that have no working upstream gateway or BGP routing.

### Egress Detection Mechanism
At scanner startup on the relay (`cf_scan.py`):
- Before allocating any workers or probing candidates, run a fast egress check:
  ```python
  def check_ipv6_egress(timeout=2.0) -> bool:
      try:
          s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
          s.settimeout(timeout)
          # Cloudflare public DNS IPv6 endpoint
          s.connect(("2606:4700:4700::1111", 53))
          s.close()
          return True
      except Exception:
          return False
  ```
- **Frequency**: Checked once at the beginning of each scan pass.
- **Action on Failure**: If egress check fails, `cf_scan.py` logs `(IPv6 egress unavailable on relay; falling back to IPv4 only)` and skips all IPv6 ranges.

### Mid-Scan Connectivity Drops
If upstream IPv6 connectivity drops while a scan is in flight:
- TCP connects raise `ENETUNREACH` or `ETIMEDOUT` immediately.
- Stage 1 cleanly records these candidates as unreachable (`ok: False`).
- The worker pool does not hang or deadlock; surviving IPv4 probes continue unaffected.

---

## 5. Architectural & Code Modifications

If and when client cellular conditions permit activation:

1. **`cf_scan.py`**:
   - Fetch `https://www.cloudflare.com/ips-v6` on bot host with built-in fallback `CF_V6_FALLBACK`.
   - Implement the $O(\text{limit})$ on-the-fly random sampler.
   - Switch socket calls dynamically:
     ```python
     family = socket.AF_INET6 if ":" in ip else socket.AF_INET
     s = socket.socket(family, socket.SOCK_STREAM)
     ```
2. **`scanner_engine.py`**:
   - Cloudflare API client requires `AAAA` record operations:
     - `create_aaaa(zone_id, name, content)`
     - `update_aaaa(zone_id, rec, content)`
     - `find_aaaa_record(zone_id, name)`
3. **`store.py`**:
   - Support candidate records with `"family": "v6"` or bracketed strings.

---

## 6. Rejected: Alternative TLS Ports

The proposal to scan alternative Cloudflare TLS ports (`2053, 2083, 2087, 2096, 8443`) in addition to `443` has been **rejected and dropped**.

### Rationale for Rejection
1. **DNS Architecture Mismatch**: The entire output of `cloudbot`'s clean-IP pipeline is a Cloudflare DNS `A` (or `AAAA`) record. DNS `A` records map hostnames to IP addresses; they do not and cannot specify a port number.
2. **Subscription Profile Invalidation**: Changing the connection port from `443` to e.g. `8443` requires regenerating and redistributing client subscription profiles (V2Ray/Xray configs) to all end-users. This changes the blast radius from an invisible, seamless DNS repoint to an operational client configuration redeployment.
3. **Arbitrary Penalty Arbitrage**: Attempting to rank ports with an arbitrary penalty (e.g. $+15.0$) has no empirical basis and risks routing traffic to unstable or firewalled non-standard ports.
