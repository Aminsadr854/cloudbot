# Pull Request Review Guide — v3.1 Architecture & Scanner Overhaul

This guide outlines the critical focus areas in PR #1 (`scanner-fixes` into `main`) to assist with code review across the 35+ commits. It highlights the five areas most deserving of careful scrutiny, followed by a frank self-assessment of the least confident design decisions.

---

## 1. Shell Argument Escaping in `cfscanner`

### What it does
Constructs and dispatches scanning commands from the bot host to the Iran relay over SSH. It serializes CLI parameters, paths, and filters into command strings executed under a remote shell with elevated file descriptor limits (`ulimit -n 65535`) and timeout wrappers.

### Files and lines to read
- `cfscanner.py`: lines 153–193 (`_build_scan_args`)
- `cfscanner.py`: lines 306–312 (`rename_cmd` construction)
- `cfscanner.py`: lines 316–326 (`cmd` assembly and execution)
- `cfscanner.py`: lines 333, 335 (`pkill` execution on timeout)
- `cfscanner.py`: line 342 (`cat` execution to retrieve result payload)

### What would go wrong if subtly wrong
- **Arbitrary Command Injection:** If arguments (e.g. hostnames, SNI values, exclude lists, or file paths) contained unescaped shell metacharacters (`;`, `&`, `|`, `$`, backticks), any untrusted input could execute arbitrary code as `root` on the remote relay.
- **Double Escaping / Argument Corruption:** If arguments were quoted inside `_build_scan_args()` and then joined with `shlex.join()`, the remote Python process would receive literal quote characters in `sys.argv`, breaking `--host`, `--sni`, or IP candidate filters.
- **Cat Command Failure:** If the output retrieval (`cat`) was bundled inside the timeout wrapper or improperly quoted, scan timeouts or paths with special characters would prevent results from being ingested.

### What specifically to check
- **Argument Array Separation:** In `_build_scan_args()` (lines 153–193), verify that elements are added to `args` as raw, unquoted strings (e.g., `"--host", host`), without calling `shlex.quote()` on each argument.
- **Whole-Command Join:** At line 325, confirm that `shlex.join(args)` is used to construct the argument string passed to `timeout`, ensuring Python's standard library handles argument quoting in one uniform pass.
- **Discrete Cat Execution:** At line 342, verify that `cat {shlex.quote(out_file + '.json')}` is run in a separate `conn.run()` invocation, independent of the scan execution pipeline, and quotes `out_file + '.json'` directly.
- **Strict IP Sanitisation:** At lines 180, 184, 190, and 215, verify that candidate/exclude filters enforce `all(ch in "0123456789." for ch in i)`, preventing malformed strings from reaching CLI flags.
- **Atomic Rename Quoting:** In lines 306–312, verify that every source and destination operand in `rename_cmd` (`tmp_path`, `remote_script`, `tmp_ranges_path`, `remote_ranges_file`, etc.) is wrapped in `shlex.quote()`.

---

## 2. DNS Rollback Path in `scanner_engine`

### What it does
When an engine identifies an optimal IP candidate and Cloudflare automatic updates are enabled, it applies the update via Cloudflare API. It then conducts a 25-second post-DNS confirmation loop (`DOMAIN_POSTCONFIRMED`) testing the domain over TLS. If post-DNS validation fails, it triggers an automated rollback to revert the record or delete a newly created record.

### Files and lines to read
- `scanner_engine.py`: lines 650–678 (record creation vs update tracking)
- `scanner_engine.py`: lines 680–697 (post-DNS confirmation loop)
- `scanner_engine.py`: lines 698–726 (automated rollback and record ID validation)
- `scanner_engine.py`: lines 727–745 (operator alert notification)

### What would go wrong if subtly wrong
- **Accidental Deletion of Production Records:** If `delete_record()` deleted records purely by FQDN or without verifying that the existing Cloudflare record ID matches `created_rec_id`, any concurrent change or pre-existing record could be permanently destroyed, taking customer traffic completely offline.
- **Crashing on Reversion:** If an engine attempted to restore `previous_live_ip` when no prior record existed (`previous_live_ip is None`), the API call would fail or create a corrupted DNS record.
- **Uncaught Exceptions in Rollback:** If Cloudflare API errors during rollback were unhandled, the scanner loop would crash and kill scheduled engine passes.

### What specifically to check
- **Creation Tracking:** In lines 650–668, verify that `record_created` is only set to `True` when `rec is None` and `cf.create_a()` is invoked. Check that `created_rec_id` captures the new record ID (handling both dictionary returns and object lookups via `refetch`).
- **Record ID Matching:** At line 706, verify the condition:
  `if cur_rec and created_rec_id and cur_rec.get("id") == created_rec_id:`
  Confirm that `cf.delete_record()` is ONLY invoked if the live Cloudflare record has the exact ID created in that pass.
- **Safety Valve on Mismatch:** At lines 710–713, verify that if `cur_rec.get("id") != created_rec_id`, the deletion is aborted, `manual_needed = True` is set, and a high-priority warning is logged and messaged to the operator.
- **Fresh Record Data on Update:** At line 719–721, verify that when rolling back an update, `cf.update_a(zone[0], cur_rec, previous_live_ip)` uses the freshly fetched `cur_rec` object rather than stale metadata.

---

## 3. Stale-Result Rejection and Atomic Writes

### What it does
Prevents the bot host from ingesting stale scan results from prior runs or reading half-written JSON files caused by timeouts or process terminations. Ensures output files are written to `.tmp` files with `fsync()` before being atomically renamed, and injects `scan_start` and `engine_id` metadata into the payload for validation by the consumer.

### Files and lines to read
- `cf_scan.py`: lines 601–646 (`write_results` atomic flush and rename)
- `cf_scan.py`: lines 607–610 (`_write_lock` re-entrancy prevention)
- `cf_scan.py`: lines 702–709 (`_sigterm_handler` writing partial results)
- `cfscanner.py`: line 287 (`scan_start_time` capture)
- `cfscanner.py`: lines 349–369 (payload validation, timestamp check, engine ID verification)

### What would go wrong if subtly wrong
- **Silent Use of Stale Candidates:** If a scan failed to run or crashed before writing results, but an old results file remained on disk from hours earlier, the consumer would read the old results and promote obsolete or blocked IPs as "freshly scanned".
- **JSON Corruptions on Interruption:** If `write_results()` wrote directly to `out_file.json` and the process was terminated by `SIGTERM` or `SIGKILL`, the bot host would encounter `json.JSONDecodeError`, aborting the pass.
- **Cross-Engine Contamination:** If multiple engines wrote to colliding paths, an engine could ingest results produced by a different engine scanning with different parameters (e.g. SNI mismatch).

### What specifically to check
- **Flush and Fsync:** In `cf_scan.py` lines 639–641, verify that `f.flush()` and `os.fsync(f.fileno())` are called before `os.replace(tmp_json, f"{out_base}.json")`, guaranteeing data reaches physical storage before atomic directory entry replacement.
- **Signal Re-entrancy Lock:** In `cf_scan.py` lines 607–610, verify that `_write_lock` prevents a `SIGTERM` handler from clobbering an ongoing `write_results()` call.
- **Grace Window Comparison:** In `cfscanner.py` line 353:
  `if file_start is not None and file_start < (scan_start_time - 5):`
  Confirm that the 5-second grace window accommodates reasonable clock drift between the bot host and relay while still strictly rejecting outputs from previous scan passes.
- **Engine ID Validation:** In `cfscanner.py` lines 358–361, confirm that `file_engine != engine_id and file_engine != 0` raises `StaleResultError`, isolating engines from cross-talk.

---

## 4. `store.py` Migration from Legacy Blocked IPs

### What it does
Migrates legacy blocked IP records from the unstructured JSON blob stored in `settings.k = 'blocked_ips'` into the normalized `blocked_ip_failures (ip, ts)` table. Normalizes single timestamps and timestamp arrays, deletes the obsolete settings key, and enables 72-hour sliding window pruning and 24-hour frequency queries.

### Files and lines to read
- `store.py`: lines 754–777 (`_migrate_blocked_ips_if_needed`)
- `store.py`: lines 786, 800 (lazy migration triggers in `mark_blocked` and `blocked_ips`)
- `store.py`: lines 791–792 (72-hour pruning in `mark_blocked`)
- `store.py`: lines 803–811 (self-join query in `blocked_ips`)

### What would go wrong if subtly wrong
- **Silent Data Loss:** If the migration queried `blocked_ips_failures` (the table name) instead of `'blocked_ips'` (the legacy setting key), it would find no records and silently delete or ignore all prior failure history without raising an error.
- **Transaction Rollback Failure:** If the legacy row deletion was not wrapped in the same database transaction as the batch insertion, an error mid-migration could delete history without writing the normalized rows.
- **Format Incompatibility:** Legacy data stored either scalar numbers (`{ip: ts}`) or lists (`{ip: [ts1, ts2]}`). Failing to parse both would drop failure entries.

### What specifically to check
- **Exact Settings Key Name:** At line 757, verify that the query specifically selects `k = 'blocked_ips'`:
  `row = self.con.execute("SELECT v FROM settings WHERE k = 'blocked_ips'").fetchone()`
- **Atomic Migration Transaction:** In lines 756–776, verify that `SELECT`, `DELETE FROM settings WHERE k = 'blocked_ips'`, and `executemany("INSERT INTO blocked_ip_failures ...")` are enclosed in `with self.con:`.
- **Type Discrimination:** In lines 769–774, verify that both `isinstance(val, (int, float))` and `isinstance(val, list)` are handled and converted to float timestamps.
- **Sliding Window Join:** In lines 803–811, verify that the self-join condition `b.ts >= a.ts AND b.ts <= a.ts + ?` and `HAVING COUNT(*) >= ? AND max(b.ts) >= ?` properly filters by `BLOCK_WINDOW_SECONDS` (24h) and `BLOCK_EXPIRY_SECONDS` (72h).

---

## 5. The `pgrep` Bracketed Pattern

### What it does
Constructs a regular expression for `pgrep -f` and `pkill -f` that matches the remote scanner script path (e.g. `/root/.cf_scan_engine_1.py`) while preventing `pgrep` from matching its own parent shell command line.

### Files and lines to read
- `cfscanner.py`: lines 44–55 (`_process_pattern`)
- `cfscanner.py`: lines 209, 276, 281, 285, 333, 335 (`proc_pattern` usage)

### What would go wrong if subtly wrong
- **Guaranteed Self-Match False Alarms:** When `conn.run(f"pgrep -f {remote_script}")` executes, the wrapper shell itself contains `remote_script` on its command line. Unbracketed, `pgrep -f` matches its own command line on every execution. Every clean scan pass would falsely conclude that a previous scan was stuck, log a spurious warning, and fire `pkill -15` / `pkill -9`.
- **Killing Unrelated Processes:** In a multi-engine environment where engine 1 is actively running a scan and a manual scan is triggered, the false self-match would kill engine 1's live scanner mid-pass.

### What specifically to check
- **Basename Isolation:** At line 50:
  `dirname, basename = os.path.split(remote_script)`
  Verify that `os.path.split()` isolates the basename so that path separators in the directory path (`/root/`) are not corrupted.
- **First Alphabetic Character Bracketed:** In lines 51–54, verify that only the first alphabetic character is enclosed in brackets (e.g., transforming `.[c]f_scan...`). This ensures the regex matches the literal script name, while the literal shell command line contains the bracketed character class and fails to match itself.
- **Shell Quoting of Pattern:** In lines 276, 281, and 333, confirm that `shlex.quote(proc_pattern)` is always used so remote shells do not treat `[...]` as a filesystem glob.

---

## What I am least confident about

Across the 35+ commits in this branch, the following three components carry the highest risk of unexpected behavior in production, because verification relied primarily on synthetic unit tests rather than multi-day operational observation:

### 1. Diurnal Recovery Dynamics of the 24-Hour Half-Life in `cf_prefix_stats` (`store.py:848–895`)
- **Why:** The exponential decay model (`0.5 ** (dt / 86400.0)`) applies mathematical decay to sample counts and success ratios to bias future scan passes away from dead /24 prefixes. While unit tests verified that the decay math behaves as expected across simulated time jumps, network disruption in Iran is heavily diurnal and episodic (e.g. targeted throttling during evening hours). It remains unverified against live traffic whether a 24-hour half-life recovers quickly enough when an operator unblocks a prefix the following morning, or whether a single bad evening permanently starves a /24 prefix from candidate exploration because biased sampling deems it "dead".
- **Risk Area:** Scanner exploration getting stuck in a local minimum or unnecessarily avoiding healthy IP subnets due to over-aggressive historical penalty retention.

### 2. SQLite Write Contention during Coincident Filtering Waves (`store.py:803–811`)
- **Why:** The self-join query in `blocked_ips()` (`JOIN blocked_ip_failures b ON a.ip = b.ip AND b.ts >= a.ts ...`) scales quadratically with the number of failure rows recorded per IP within a 24-hour window. While synthetic benchmarks with 2,000 IPs and 50 dense clusters executed in ~4ms on an unloaded database, this test assumed zero write contention. In production, `blocked_ips()` is executed across three concurrent engines, while mobile handsets continuously submit negative probe reports via `probeapi.py` into SQLite. SQLite's database-level locking during `executemany` failure inserts and 72-hour pruning sweeps could produce `sqlite3.OperationalError: database is locked` or transient latency spikes under real-world nationwide disruption waves.
- **Risk Area:** Bot scheduler timeouts or missed scan windows if database lock contention coincides with nationwide carrier filtering events.

### 3. Relay Socket Exhaustion Under Concurrent Multi-Engine Sweeps (`cfscanner.py:run_scan`)
- **Why:** Engine script paths and result files were verified to be isolated, and a single-engine live test on engine 9 confirmed clean execution on the Iran relay. However, running all three engines concurrently against the Iran relay has never been executed live. Each engine pass raises `ulimit -n 65535` and opens hundreds of concurrent outbound TLS probes to Cloudflare edge IPs. If all three engines initiate sweeps simultaneously, the aggregate network socket and TCP connection rate could trigger outbound connection limits or conntrack table exhaustion on the relay's hosting provider, causing synthetic probe failures that the scanner will misinterpret as operator censorship.
- **Risk Area:** False-positive candidate rejections caused by local relay bandwidth/socket saturation rather than actual Cloudflare IP blockages.
