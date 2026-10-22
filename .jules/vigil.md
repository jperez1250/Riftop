# Vigil's Journal — Critical Testing Insights

## 2025-02-22 - Non-Monotonic Time Regression Testing Pattern
**Challenge:** Testing time-sensitive data structures (`FlowTable`, `AlertEngine`, `RateWindow`) with simulated packet timestamps or snapshot evaluations can cause standard `Instant::duration_since` to panic if time regresses or packets arrive out-of-order.
**Strategy:** Standardized unit tests to explicitly pass regressed `Instant` timestamps (`t0 < t1`) into time-dependent functions to prove panic resilience.
**Prevention:** Always use `Instant::saturating_duration_since` across all rate calculations, alert evaluations, and table expiration logic to guarantee zero-panic bounds during out-of-order packet processing and time regressions.
