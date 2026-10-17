# Vigil's Journal - Critical QA & Testing Insights

## 2025-05-18 - Safe Instant Boundary Testing Under Time Regression
**Challenge:** Network monitoring applications like Riftop record timestamps from packet arrivals and snapshot evaluations using `std::time::Instant`. Out-of-order packet timestamps or clock synchronization adjustments can result in evaluating methods with `now < last_seen` or `now < prev`.
**Strategy:** When testing stateful timing components like `FlowTable::expire` and `AlertEngine::evaluate`, construct explicit test cases where evaluated timestamps regress relative to previously recorded internal timestamps.
**Prevention:** Verify that timing calculations strictly use non-panicking method calls (e.g., `Instant::saturating_duration_since` or safe subtraction guards) rather than standard `duration_since` or direct timestamp subtraction, ensuring resilience against system clock jumps or packet out-of-order delivery.
