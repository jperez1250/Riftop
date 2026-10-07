# Bloodhound's Journal - Critical Learnings Only

## 2025-05-18 - Instant Duration Panic on Out-of-Order Timestamps
**Issue:** `FlowTable::expire` and `AlertEngine::evaluate` used standard `Instant::duration_since`, which can panic if passed a timestamp `now` that is earlier than a flow's `last_seen` timestamp or previous alert check instance (e.g. out-of-order PCAP packets, clock adjustments, or capacity eviction during packet processing).
**Fix:** Replaced `now.duration_since(...)` with `now.saturating_duration_since(...)` across table flow expiration and PPS alert calculations.
**Prevention:** Always use `Instant::saturating_duration_since` when calculating elapsed time between packet timestamps or snapshot instances that may arrive out of order or regress, and write regression tests that evaluate time bounds with backward time jumps.
