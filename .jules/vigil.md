# Vigil's Testing Journal

## 2025-10-18 - Out-of-Order Timestamp Regression in Flow Expiration & Alert Evaluation
**Challenge:** Network packet streams and replayed PCAPs can present non-monotonic or regressed packet timestamps (`now < last_seen` or `now < prev`). Standard library calls like `now.duration_since(...)` panic on timestamp regressions under panic-on-underflow mode.
**Strategy:** Tested `AlertEngine::evaluate` and `FlowTable::expire` against backward time jumps and verified that `saturating_duration_since` prevents thread panics when evaluating flows or calculating global PPS metrics with out-of-order timestamps.
**Prevention:** Always use `saturating_duration_since` when computing time deltas between packet timestamps, snapshot instances, or thread ticks across the capture pipeline.
