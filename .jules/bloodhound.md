# Bloodhound's Journal - Critical Functional Bug Findings

## 2025-02-22 - FlowTable Expire Out-of-Order Timestamp Panic
**Issue:** `FlowTable::expire` called `now.duration_since(s.last_seen)` to check flow idle duration. If packet timestamps arrived out of order or regressed relative to `now`, `duration_since` panicked at runtime because `now < s.last_seen`.
**Fix:** Changed `now.duration_since(s.last_seen)` to `now.saturating_duration_since(s.last_seen)`.
**Prevention:** Always use `Instant::saturating_duration_since` when calculating elapsed time between timestamps that could potentially arrive out of temporal sequence in packet capture streams or asynchronous events.
