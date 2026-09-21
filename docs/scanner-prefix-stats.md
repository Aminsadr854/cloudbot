# Design Specification: Per-/24 Prefix Statistics and Biased Sampling (Task D2 Step 2)

## 1. Overview and Rationale

Cloudflare routes traffic and assigns edge configurations at prefix granularity—primarily `/24` IPv4 blocks (~5,956 subnets across announced ranges). In Iran's network environment, censorship filters and routing blackholes typically target entire `/24` subnets rather than individual addresses.

Currently, every scan pass samples the ~1.5M address space uniformly with no memory of previous runs. This wastes 70–80% of probe packets probing known-dead or heavily filtered subnets. 

Task D2 Step 2 introduces persistent prefix-level telemetry in `store.py` to bias candidate generation toward high-performing `/24` blocks while maintaining continuous exploration of the remaining address space.

---

## 2. Telemetry and Storage Schema

### Where Data is Stored
Prefix statistics are stored in the central SQLite database managed by `store.py`. A dedicated table `cf_prefix_stats` is used rather than serialised JSON to allow sub-millisecond lookups, indexed updates, and atomic decays across ~6,000 subnets.

### Table Schema
```sql
CREATE TABLE IF NOT EXISTS cf_prefix_stats (
    prefix TEXT PRIMARY KEY,       -- e.g. "104.16.12.0/24"
    samples REAL DEFAULT 0.0,      -- Decayed addresses probed in this /24
    successes REAL DEFAULT 0.0,    -- Decayed addresses reaching valid edge response
    score_sum REAL DEFAULT 0.0,    -- Decayed sum of cfscanner scores for responsive IPs
    last_sampled REAL DEFAULT 0.0, -- Epoch timestamp of most recent probe
    last_success REAL DEFAULT 0.0  -- Epoch timestamp of most recent valid edge response
);
CREATE INDEX IF NOT EXISTS idx_prefix_stats_last_sampled ON cf_prefix_stats (last_sampled);
```

### Table Size and Resource Footprint
Cloudflare's announced IPv4 address space comprises exactly 5,956 `/24` subnets across 15 CIDRs. Consequently, `cf_prefix_stats` contains at most **~6,000 rows**, occupying approximately **400–600 KB on disk**.

---

## 3. Aggregation and Transport Across SSH

To minimize network overhead and database contention:
1. **Aggregation on the Relay**: During a scan pass, `cf_scan.py` tracks probes by `/24` prefix as they occur in memory:
   - `samples`: Number of addresses in that `/24` probed in Stage 1/2.
   - `successes`: Number of addresses achieving a valid Cloudflare edge response with `cf-ray`.
   - `score_sum`: Sum of canonical scores for candidates reaching the stability stage.
2. **What Crosses SSH**: `cf_scan.py` embeds a compact `prefix_stats` dictionary into the results JSON written at `out_file + ".json"`. In a typical pass visiting ~500 subnets, this payload is **~20 KB**.
3. **Bot-Host Ingestion (Single Transaction)**: When `cfscanner.run_scan()` receives the JSON results, `scanner_engine.py` calls `store.record_prefix_stats(prefix_stats)`. The store executes a single **`executemany` statement inside one atomic SQLite transaction**, updating all 500 rows in $< 5$ milliseconds.

---

## 4. Sampling Strategy: Exploitation vs. Exploration

Candidate selection splits the subnet sampling budget into **Exploitation (70%)** and **Exploration (30%)**:

```
                           Total Subnet Budget (N)
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
       Exploitation (70%)                      Exploration (30%)
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ Proven prefixes meeting      │        │ Unexplored prefixes, newly   │
 │ minimum yield, weighted by   │        │ announced blocks, or blocks  │
 │ decayed score and yield      │        │ not sampled in > 48 hours    │
 └──────────────────────────────┘        └──────────────────────────────┘
```

### Module Constants
```python
EXPLORATION_RATIO = 0.30         # 30% of candidate budget dedicated to exploration
EXPLOITATION_MIN_YIELD = 0.10    # Minimum 10% valid responses required for exploitation
EXPLOITATION_MIN_SAMPLES = 3.0   # Minimum decayed samples needed before eligible
HALF_LIFE_SECONDS = 24 * 3600    # 24-hour exponential decay half-life
AGING_CUTOFF_SECONDS = 48 * 3600 # 48 hours without samples forces return to exploration
```

### A. Exploitation (70% Allocation)
- Filter prefixes where:
  $$\text{samples}_{\text{decayed}} \ge \text{EXPLOITATION\_MIN\_SAMPLES} \quad \text{and} \quad \text{yield}_{\text{decayed}} \ge \text{EXPLOITATION\_MIN\_YIELD}$$
- Metric definitions:
  - **Decayed Yield**: $\text{yield}_{\text{decayed}} = \frac{\text{successes}_{\text{decayed}}}{\text{samples}_{\text{decayed}}}$
  - **Decayed Mean Score ($\bar{S}$)**: $\bar{S} = \frac{\text{score\_sum}_{\text{decayed}}}{\text{successes}_{\text{decayed}}}$
    *(where score is the canonical metric $S = \text{rtt} + 4 \times \text{jitter} + 50 \times \text{loss}$)*
- **Selection Weight**:
  $$W_{\text{prefix}} = \frac{\text{yield}_{\text{decayed}}}{\bar{S} + 1.0}$$
  All calculations strictly use **decayed** values, ensuring recently verified subnets outrank prefixes that were good in the past.
- Subnets are sampled without replacement proportional to $W_{\text{prefix}}$.

### B. Exploration (30% Allocation)
- Allocates 30% of subnets to prefixes that:
  1. Have never been sampled ($\text{samples} == 0$), OR
  2. Have not been sampled recently ($\text{now} - \text{last\_sampled} > \text{AGING\_CUTOFF\_SECONDS}$).
- Sampled uniformly at random using the C1 Fisher-Yates generator.

---

## 5. Aging, Recovery, and Range List Changes

### Exponential Time-Decay
Historical counters decay continuously with a 24-hour half-life ($\tau_{1/2} = 24\text{ hours}$):
$$\text{metric}(t) = \text{metric}(t_0) \times 2^{-\frac{t - t_0}{\tau_{1/2}}}$$
- After 24 hours of silence, negative failure counts lose 50% of their weight.
- After 48 hours, the prefix crosses the aging cutoff and automatically re-enters the 30% exploration bucket, giving recovered or unblocked prefixes a fresh probe opportunity.

### Handling Cloudflare Range List Changes
- **Newly Announced Ranges**: When `_get_cached_ranges()` discovers a newly announced CIDR block, its decomposed `/24` subnets do not exist in `cf_prefix_stats`. With $\text{samples} = 0$, they are classified as unexplored and immediately enter the 30% exploration queue.
- **Withdrawn/Stale Prefixes**: When the range list updates or during store maintenance, any prefix in `cf_prefix_stats` not present in the current `cloudflare_ranges()` list is purged:
  ```sql
  DELETE FROM cf_prefix_stats WHERE prefix NOT IN (...);
  ```

---

## 6. Cold Start Behavior

When `cf_prefix_stats` is empty or holds $< 100$ recorded subnets:
1. The exploitation pool contains 0 eligible subnets ($\text{samples} < 3$).
2. The exploration fraction automatically becomes **100%**.
3. Candidate generation runs pure uniform random sampling across all Cloudflare `/24`s (identical to C1 baseline).
4. Results from early passes populate the table. Within 2–3 scan windows, the 70/30 split naturally stabilizes.
