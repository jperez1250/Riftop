## 2025-02-18 - Prevent Panics on Out-of-Order Timestamp Duration Calculation
**Issue:** `FlowTable::expire` and `AlertEngine::evaluate` used `Instant::duration_since`, which panics at runtime if `now` is earlier than an entry's `last_seen` or `last_check` timestamp (e.g. out-of-order packets or clock regression/jitter).
**Fix:** Replaced `duration_since` calls with `saturating_duration_since`, safely returning `Duration::ZERO` when timestamps regress.
**Prevention:** Always use `Instant::saturating_duration_since` when calculating elapsed time between packet timestamps or snapshot instances that may arrive out of order.
