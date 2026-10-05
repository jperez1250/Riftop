## 2025-02-28 - Non-Monotonic Instant Calculation and Floating Point Boundary Limits

**Issue:** Calling `Instant::duration_since` when timestamps arrive out of order, or when `now` regresses relative to flow timestamps or alert state, causes a runtime panic (`'specified instant was later than self'`). Furthermore, rate calculations with zero-duration `max_age` or `NaN` inputs caused floating-point division by zero (`inf`) and potential `f64::clamp` panics.
**Fix:** Changed `now.duration_since(...)` to `now.saturating_duration_since(...)` in `FlowTable::expire` and `AlertEngine::evaluate`. Added zero-duration guards in `RateWindow::rate` and `rate.is_nan()`/`max_rate.is_nan()` checks in `rate_bar`.
**Prevention:** Always use `saturating_duration_since` when computing deltas between packet/event timestamps, and defend against zero durations or NaN floating point values in rate rendering functions.
