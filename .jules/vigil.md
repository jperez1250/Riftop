# Vigil's Testing Journal & Critical QA Insights

## 2025-05-18 - Flow Snapshot Rate Evaluation in Unit Tests
**Challenge:** Unit testing `AlertEngine` requires constructing mock `Snapshot` instances with `FlowStats`. Calling `FlowStats::record_endpoints` records direction-specific byte counters (`bytes_a_to_b`), but `FlowStats::rate_10s` evaluates total flow rate populated via `FlowStats::record`.
**Strategy:** Ensure unit tests populate total flow rate via `stats.record(...)` or both `record` and `record_endpoints` so that total rate windows update correctly during `AlertEngine::evaluate`.
**Prevention:** When testing components consuming `Snapshot` flow rates, verify that `FlowStats::record` is invoked with valid sample timestamps and direction flags.
