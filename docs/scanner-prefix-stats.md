# Design Specification: Per-/24 Prefix Statistics and Biased Sampling (Task D2 Step 2)

## 1. Overview and Rationale

Cloudflare routes traffic and assigns edge configurations at prefix granularity—primarily `/24` IPv4 blocks (~5,956 subnets across announced ranges). In Iran's network environment, censorship filters and routing blackholes typically target entire `/24` subnets rather than individual addresses.

Currently, every scan pass samples the ~1.5M address space uniformly with no memory of previous runs. This wastes 70–80% of probe packets probing known-dead or heavily filtered subnets. 

Task D2 Step 2 introduces persistent prefix-level telemetry in `store.py` to bias candidate generation toward high-performing `/24` blocks while maintaining continuous exploration of the remaining address space.

---

## 2. Telemetry and Storage Schema

### Where Data is Stored
Prefix statistics will be stored in the central SQLite database managed by `store.py`. A dedicated table `cf_prefix_stats` is used rather than serialised JSON to allow sub-millisecond lookups, indexed updates, and atomic decays across ~6,000 subnets.

### Table Schema
```sql
CREATE TABLE IF NOT EXISTS cf_prefix_stats (
    prefix TEXT PRIMARY KEY,       -- e.g. "104.16.12.0/24"
    samples INTEGER DEFAULT 0,     -- Total addresses probed in this /24
    successes INTEGER DEFAULT 0,   -- Addresses reaching HTTP/TLS edge check
    score_sum REAL DEFAULT 0.0,    -- Sum of cfscanner scores for responsive IPs
    last_sampled REAL DEFAULT 0.0, -- Epoch timestamp of most recent probe
    last_success REAL DEFAULT 0.0  -- Epoch timestamp of most recent valid edge response
);
CREATE INDEX IF NOT EXISTS idx_prefix_stats_last_sampled ON cf_prefix_stats (last_sampled);
```

### Prefix Metrics
- **Yield Rate ($Y$)**: $Y = \frac{\text{successes}}{\text{samples}}$ (fraction of probed IPs answering validly).
- **Average Quality ($\bar{S}$)**: $\bar{S} = \frac{\text{score\_sum}}{\text{successes}}$ (lower score indicates lower latency and jitter; cfscanner canonical score formula).

---

## 3. Sampling Strategy: Exploitation vs. Exploration

To avoid missing newly responsive subnets or getting trapped in local optima, candidate selection splits the sampling budget into **Exploitation (70%)** and **Exploration (30%)**.

```
                           Total Subnet Budget (N)
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
       Exploitation (70%)                      Exploration (30%)
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ Top-scoring prefixes with    │        │ Unexplored prefixes or       │
 │ proven yield and low latency │        │ prefixes not probed in > 48h │
 └──────────────────────────────┘        └──────────────────────────────┘
```

### A. Exploitation (70% of Subnet Allocation)
- Filter prefixes where $\text{samples} \ge 3$ and $\text{yield} \ge 0.5$.
- Compute prefix desirability weight:
  $$W_{\text{prefix}} = Y \times \frac{1}{\bar{S} + 1.0}$$
- Sample subnets without replacement proportional to $W_{\text{prefix}}$.

### B. Exploration (30% of Subnet Allocation)
- Identifies subnets that either:
  1. Have never been sampled ($\text{samples} == 0$), or
  2. Have not been sampled within the aging window ($\text{now} - \text{last\_sampled} > 48\text{ hours}$).
- Sampled uniformly at random using the C1 Fisher-Yates generator.

---

## 4. Aging and Recovery (Avoiding Permanent Blacklisting)

Censorship in Iran is dynamic: subnets that are filtered today may be unblocked tomorrow, and routing paths change frequently. Permanent blacklisting would eventually deplete clean subnets.

### Exponential Time-Decay
When reading statistics or on a periodic maintenance cycle (e.g. daily store tick), sample counts and success counts are aged using exponential decay:
$$\text{metric}_{\text{decayed}} = \text{metric} \times e^{-\frac{\Delta t}{\tau}}$$
- **Half-Life ($\tau_{1/2}$)**: Set to **24 hours** ($\tau = \frac{24 \times 3600}{\ln 2} \approx 124,700\text{ seconds}$).
- After 24 hours without probes, past failures lose 50% of their negative weight.
- After 72 hours without probes, past history decays to $< 12.5\%$, and the subnet is automatically classified as "unexplored", shifting it into the 30% exploration bucket.

---

## 5. Cold Start Behavior

When a fresh database is initialized or when prefix statistics are cleared:
1. `cf_prefix_stats` contains 0 records.
2. The exploitation pool has 0 eligible candidates ($\text{samples} < 3$).
3. The exploration fraction automatically scales to **100%**.
4. The scanner falls back to pure uniform random candidate generation across all Cloudflare `/24` subnets (identical to the current C1 implementation).
5. As passes run and write results back to the store, subnets transition from unexplored to the exploitation pool once they record $\ge 3$ samples. Within 2–3 full windows, the 70/30 split naturally stabilizes.

---

## 6. Component Interactions and Interfaces

1. **Bot Engine (`scanner_engine.py`)**:
   - At the start of `scan_pass`, queries `store.get_prefix_weights()`.
   - Passes prioritized prefixes and exclusion lists to `cfscanner.run_scan()`.
   - At the end of `scan_pass`, calls `store.record_prefix_samples(results, sampled_subnets)`.
2. **Scanner CLI (`cf_scan.py`)**:
   - Accepts `--preferred-prefixes-file` or `--prefix-weights` alongside `--exclude` and `--ranges-file`.
   - Applies the 70/30 split during the C1 candidate subnet shuffle.
3. **Store (`store.py`)**:
   - Implements `get_prefix_weights()`, `record_prefix_stats()`, and periodic decay.
