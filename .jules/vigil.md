# Vigil's Testing Journal

## 2025-05-18 - Out-of-Order Timestamp & Clock Skew Regression Prevention
**Challenge:** Testing real-time packet capturing and flow evaluation code against out-of-order packet timestamps or backwards clock adjustments. Standard Rust `Instant::duration_since` panics when `now < previous`, which can occur in live network packet capture threads or during clock synchronization.
**Strategy:** Construct unit test cases that explicitly pass regressed `Instant` timestamps (`now_past = now - Duration::from_secs(N)`) into rate computation, flow table expiration (`FlowTable::expire`), and alert evaluation (`AlertEngine::evaluate`).
**Prevention:** Always use `Instant::saturating_duration_since` instead of `duration_since` across all rate windows, expirations, and metric engine loops to prevent panic risks on non-monotonic or out-of-order time inputs.
