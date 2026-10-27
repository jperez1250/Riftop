# Vigil's Journal - Critical Testing Insights

## 2026-03-30 - Out-of-Order Time Evaluation in Alert Engine
**Challenge:** Testing `AlertEngine::evaluate` under out-of-order time evaluation (where snapshot timestamps regress relative to `last_check`) exposed a potential panic in `Instant::duration_since(prev)`.
**Strategy:** Added unit test `test_out_of_order_evaluation_time_regression_panic` in `src/alerts.rs` verifying that evaluating snapshots out-of-order does not panic.
**Prevention:** Use `Instant::saturating_duration_since` across all rate and time delta calculations in Riftop so out-of-order samples or system time adjustments return `Duration::ZERO` safely rather than panicking.
