## 2026-03-31 - Non-monotonic Instant Subtraction Panics
**Issue:** Subtraction of `Instant` using `now.duration_since(previous_ts)` panics at runtime if `now` is earlier than `previous_ts` (e.g. out-of-order packet timestamps in pcap replays, clock adjustments, or concurrent thread snapshot timings).
**Fix:** Use `now.saturating_duration_since(previous_ts)` in `FlowTable::expire` and `AlertEngine::evaluate` to defensively handle timestamp regression without panicking.
**Prevention:** Always use `saturating_duration_since` when calculating time elapsed between events or timestamps in flow calculations and metrics evaluation.
