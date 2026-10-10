# Bloodhound's Journal - Critical Learnings

## 2025-02-17 - Out-of-Order Timestamp Merging and Duration Panics
**Issue:** `saturating_duration_since` returns `Duration::ZERO` when `now < *last_ts`. In `RateWindow::add`, checking `now.saturating_duration_since(*last_ts) < 100ms` evaluated to `0 < 100ms` for ALL out-of-order packet timestamps in the past, causing old packets (even minutes old) to be merged into the current 100ms sample bucket. Additionally, calling non-saturating `now.duration_since(last_seen)` in `FlowTable::expire` or `AlertEngine::evaluate` caused runtime panics whenever timestamps regressed.
**Fix:**
1. In `RateWindow::add`, explicitly check orientation (`now >= *last_ts` vs `now < *last_ts`) before testing if the difference is `< 100ms`.
2. In `FlowTable::expire` and `AlertEngine::evaluate`, use `now.saturating_duration_since` to handle out-of-order or regressed timestamps gracefully without panicking.
3. In `RateWindow::add`, use `saturating_add` on `*last_bytes` to prevent arithmetic overflow.
**Prevention:** Always verify directional ordering (`a >= b`) before calling `saturating_duration_since` in windowing algorithms, and test rate windows with out-of-order packets.
