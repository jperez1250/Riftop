# Bloodhound's Journal

## 2025-05-18 - Non-Monotonic Instant Subtraction & PCAP Timestamp Overflow Flaws
**Issue:** `FlowTable::expire` and `AlertEngine::evaluate` invoked `Instant::duration_since`, which can panic or produce undefined time calculations when timestamps arrive out of order, regress, or drift. Furthermore, `process_pcap_file_filtered` directly cast signed `tv_sec` in PCAP headers to `u64`, turning negative values into `u64::MAX` and causing duration addition overflow panics (`base_instant + elapsed`).
**Fix:** Replaced `duration_since` with defensive `saturating_duration_since` in `FlowTable::expire` and `AlertEngine::evaluate`. In `process_pcap_file_filtered`, used `u64::try_from` fallback and `checked_add` to gracefully prevent duration arithmetic overflow panics on corrupted or negative timestamp headers.
**Prevention:** Always use `saturating_duration_since` for time deltas between events/snapshots, use `u64::try_from` when converting C time structures (`timeval`), and add regression tests covering out-of-order timestamps and corrupted PCAP headers.
