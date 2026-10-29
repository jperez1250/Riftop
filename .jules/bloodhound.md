## 2026-10-29 - Prevent runtime panics on regressed or out-of-order timestamps
**Issue:** Standard `Instant::duration_since(earlier)` panics if `self` is earlier than `earlier` (e.g. out-of-order packets, NTP clock sync adjustments, PCAP timestamp jitter, or mock test snapshots).
**Fix:** Replace `.duration_since()` with `.saturating_duration_since()` in `FlowTable::expire` and `AlertEngine::evaluate` to gracefully return `Duration::ZERO` on timestamp regressions.
**Prevention:** Always use `Instant::saturating_duration_since` when calculating elapsed durations between event or packet timestamps across network feeds and snapshots. Add unit tests for non-monotonic time.
