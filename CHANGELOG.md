# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-09-21

### Security
- Shell injection was possible in the remote scan command via the configured domain; all remote arguments are now escaped.
- TLS certificate validation added as an interception signal, with a guard that distinguishes a broken local trust store from real interference.

### Fixed
- Results from a previous pass could be read as fresh measurements.
- A failed measurement of the currently live address could trigger an unnecessary domain switch.
- The post-DNS confirmation never actually resolved the domain.
- Rollback left an orphaned record when the A record had just been created.
- Non-finite values leaked into the results JSON.
- Concurrent engines could corrupt each other's uploaded scanner script.
- A timed-out scan orphaned a process on the relay and lost all results.
- The remote process check matched its own command line, so every run reported a phantom previous scan and killed it.

### Changed
- Stability measurement now probes TLS as well as TCP with separate metrics, because filtering on this path occurs after the TLS handshake.
- Reachability probes retry once; connect timeout raised to 3 seconds.
- Candidate generation roughly 27x faster with 99.5% fewer allocations.
- Bounded worker pools replace unbounded task creation.
- Throughput testing capped to the top finalists, cutting per-window bandwidth.
- Scan concurrency limited across engines.
- Blocked addresses now require repeated failures and expire, instead of being blocked permanently by a single report.
- Sampling biased toward historically productive prefixes; prefixes proven dead are no longer rescanned.

### Added
- The Cloudflare range list is fetched on the bot host and shipped to the relay, with caching and a fallback chain.
- Per-prefix statistics with time decay.
- Documentation of known debt in the legacy scanner call sites.

### Validation
This release was exercised against live infrastructure with a controlled scan pass; the partial-result write on timeout and the stale-result rejection were both confirmed in the field.

### Known Limitations
The four legacy scanner call sites still default to the first engine and bypass the newer DNS safety checks — see `docs/BOT-SCANNER-DEBT.md`. Deployments upgrading from an earlier version must set the control probe host in their environment file, since it is no longer hardcoded and an unset value now produces a startup warning.
