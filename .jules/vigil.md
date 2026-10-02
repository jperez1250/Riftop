# Vigil's Journal - Critical QA & Testing Insights

## 2025-02-18 - Deterministic Time Baselines for Instant-Based Rate Windows & Expiration
**Challenge:** Riftop uses `std::time::Instant` across `RateWindow`, `FlowTable`, and `AlertEngine` for sliding rate calculations and flow expiration pruning. Real-time sleep-based testing introduces flakiness, slowness, and non-determinism into the test suite.
**Strategy:** Construct tests using a fixed base `Instant::now()` and offset future calls deterministically with synthetic relative `Duration` offsets (e.g., `now + Duration::from_secs(10)`). This allows testing window boundary pruning, rate moving averages, and flow expiration instantly without sleep delays.
**Prevention:** Always pass explicit `now: Instant` references to domain methods (`record`, `rate`, `expire`, `evaluate`) in unit and integration tests rather than relying on implicit wall-clock reads.
