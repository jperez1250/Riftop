# Vigil's Testing Journal

## 2025-05-18 - Out-of-Order Timestamp & Regressing Instant Handling
**Challenge:** Testing time-sensitive subsystems (like `AlertEngine` and `RateWindow`) when timestamps arrive out of order or regress due to non-monotonically incrementing capture packets or system clock adjustments.
**Strategy:** Use `Instant::saturating_duration_since` instead of `Instant::duration_since` in time delta calculations. Construct deterministic unit test scenarios with simulated `Instant` values shifted backwards in time to verify panic-freedom.
**Prevention:** Enforce `saturating_duration_since` across all duration difference logic in network monitoring components that accept timestamps from external capture frames or threads.
