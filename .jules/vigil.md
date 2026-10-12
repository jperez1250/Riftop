## 2025-02-18 - Safe Duration Calculations Under Time Regression
**Challenge:** Testing `AlertEngine` PPS calculations with out-of-order snapshot timestamps exposed potential panics from `Instant::duration_since(prev)` when `now < prev`.
**Strategy:** Standardized time delta calculations in `AlertEngine` to use `now.saturating_duration_since(prev)`, clamping to `.max(0.001)` to prevent panics and division-by-zero errors.
**Prevention:** Always use `saturating_duration_since` when evaluating rate or delta metrics between dynamic timestamps.
