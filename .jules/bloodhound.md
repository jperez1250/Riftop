# Bloodhound's Journal

## 2025-05-18 - Flow Expiration Panic on Timestamp Regression
**Issue:** `FlowTable::expire` called `now.duration_since(s.last_seen)` which panics if packet timestamps or current snapshot time regress/arrive out-of-order.
**Fix:** Changed `now.duration_since(s.last_seen)` to `now.saturating_duration_since(s.last_seen)` to safely return `Duration::ZERO` when `now < s.last_seen`.
**Prevention:** Always use `Instant::saturating_duration_since` when calculating elapsed time between network timestamps or snapshot instances.
