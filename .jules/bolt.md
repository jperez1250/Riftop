
## 2025-10-02 - FlowKey Copy & RateWindow Early Eviction
**Learning:** `FlowKey` only contains copyable primitives/enums, so deriving `Copy` eliminates `.clone()` allocations on `HashMap::entry()` in hot packet paths. Additionally, since `RateWindow.samples` are strictly time-sorted, checking `samples.first()` ($O(1)$) before calling `retain()` ($O(N)$) skips unnecessary vector scans on every packet when no samples are expired.
**Action:** Always check if small key types in hot hash maps can derive `Copy` and if time-series sample vectors can use early-exit boundary checks before calling `retain()`.
