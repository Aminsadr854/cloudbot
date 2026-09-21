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

Across the 35+ commits in this branch, the following three components have the weakest correctness arguments, where tests share assumptions with the implementation or where behavior was reasoned about rather than observed against live infrastructure:

### 1. The A6 Rollback Deletion Path (`scanner_engine.py:702–715`)
- **What is unverified:** The execution of `cf.delete_record(zone[0], cur_rec["id"])` against the real Cloudflare API when post-DNS confirmation (`DOMAIN_POSTCONFIRMED`) fails on a newly created record. During live validation on the relay, every selected IP passed post-DNS verification, so the rollback deletion branch has never executed against live infrastructure.
- **Why the existing test does not close it:** In `test_engines.py:test_a6_rollback_by_deleting_freshly_created_record`, Cloudflare's client is entirely mocked (`cf.delete_record`, `cf.create_a`, `cf.find_a_record` are `AsyncMock` objects). The test asserts that `delete_record` was called with the mock's returned ID. If the real Cloudflare API returns record IDs in a different data structure (e.g. integer vs string, or wrapped in a response envelope that `find_a_record` unpacks differently), or if Cloudflare requires additional parameters or headers to delete an unproxied record, the mock silently absorbs the call and passes green.
- **What would actually verify it:** Intentionally triggering a post-confirmation failure against the real Cloudflare DNS API (for example, by pointing a temporary test record at a non-responsive IP so `_verify` fails) and observing Cloudflare return HTTP 200 on `delete_record`, followed by verifying via a separate query that the record is physically deleted from the zone.

### 2. Prefix Decay Mathematics & Tautological Tests (`store.py:848–895` & `test_engines.py:1700–1745`)
- **What is unverified:** Whether the mathematical model for exponential sample and success decay (`0.5 ** (dt / 86400.0)`) correctly ranks prefixes over time, and whether non-monotonic or boundary timestamp deltas (e.g. NTP backwards steps, or multi-week gaps between scans) cause arithmetic underflow, division-by-zero, or numerical instability in SQLite storage.
- **Why the existing test does not close it:** The unit tests (`test_d2_prefix_stats_table`, `test_d2_prefix_biased_sampling`) were authored alongside the implementation and evaluate assertions using the exact same arithmetic formula (`sample * 0.5 ** (dt / 86400.0)`). If the underlying equation or state tracking has a structural flaw (such as decaying total samples while leaving raw weights unadjusted, or producing near-zero floating point denominators that distort probability sampling), both the implementation and the test share the exact same blind spot and assert agreement with the flaw.
- **What would actually verify it:** Subjecting the decay calculations to property-based tests across extreme boundary conditions (e.g. `dt < 0` for non-monotonic system clocks, `dt > 10^7` for dormant engines, zero samples with nonzero successes) and validating that the resulting selection weights remain strictly valid probability distributions across all ranges.

### 3. The `store.py` Legacy Migration against Real Historical Data (`store.py:754–777`)
- **What is unverified:** Whether `_migrate_blocked_ips_if_needed()` correctly migrates the actual shape and variety of historical failure records accumulated in real production databases across previous bot versions.
- **Why the existing test does not close it:** The test `test_d3_blocked_ip_failures_table` seeds a temporary database with synthetic JSON fixtures (`{"1.2.3.4": 1000.0, "5.6.7.8": [1000.0, 2000.0]}`) authored by the same person who wrote the migration logic. If real production databases contain legacy data with unexpected types (e.g. string timestamps from earlier revisions, `null` values, boolean flags, or IPv6 strings formatted with brackets), or if the JSON blob was stored with unexpected encodings, the synthetic test passes without proving that real historical production records will survive the upgrade.
- **What would actually verify it:** Running `_migrate_blocked_ips_if_needed()` against a sanitized copy of a real production `cloudbot.db` from before the v3.1 branch, asserting that every single failure entry present in the legacy `blocked_ips` JSON blob translates into an exact corresponding row in `blocked_ip_failures`.
