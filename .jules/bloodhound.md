## 2025-05-18 - Prevent Instant Subtraction Panic in Flow Table Expiration
**Issue:** `FlowTable::expire` used `now.duration_since(s.last_seen)`, which panics if `now` is earlier than `s.last_seen` (e.g. out-of-order packets or regressed system clocks).
**Fix:** Changed `now.duration_since(s.last_seen)` to `now.saturating_duration_since(s.last_seen)` in `FlowTable::expire` to return zero duration and prevent runtime panics when timestamps regress.
**Prevention:** Always use `saturating_duration_since` when evaluating differences between packet/flow timestamps or system evaluation instants to ensure non-monotonic timestamp regressions are handled safely without panicking.
