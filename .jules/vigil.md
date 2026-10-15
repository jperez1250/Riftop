# Vigil's QA Journal — Critical Testing Insights

## 2025-05-18 - Out-of-Order Timestamp Regression Testing & Duration Safety
**Challenge:** In high-throughput network capture applications and alert evaluation engines, timestamps between consecutive packets or snapshot samples may regress or arrive out of order (e.g. system NTP adjustments, multi-threaded capture queues, offline PCAP replay). Using stdlib `Instant::duration_since(earlier)` panics if `now < earlier`, breaking table pruning and alert evaluation.
**Strategy:** Ensure all time-delta calculations in `FlowTable::expire` and `AlertEngine::evaluate` use `Instant::saturating_duration_since(earlier)`. Author unit tests explicitly passing reverse-chronological `Instant` timestamps to verify panic-free behavior under time regressions.
**Prevention:** Enforce `saturating_duration_since` across all timestamp arithmetic in `src/flow/` and `src/alerts.rs` modules, and maintain property/boundary unit tests for out-of-order time inputs.
