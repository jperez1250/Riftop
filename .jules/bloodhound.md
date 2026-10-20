# Bloodhound's Journal - Critical Learnings

## 2025-02-17 - Prevent Panics on Non-Monotonic / Out-of-Order Timestamps
**Issue:** Using `Instant::duration_since` when comparing standard `Instant` timestamps can panic at runtime if time values regress or arrive out-of-order (`now < earlier_ts`), which occurs during out-of-order packet processing or system time adjustments in `FlowTable::expire` and `AlertEngine::evaluate`.
**Fix:** Replaced `now.duration_since(...)` with `now.saturating_duration_since(...)` in `FlowTable::expire` and `AlertEngine::evaluate`.
**Prevention:** Always use `saturating_duration_since` or `checked_duration_since` when subtracting `Instant` instances to handle non-monotonic or out-of-order temporal inputs gracefully.
