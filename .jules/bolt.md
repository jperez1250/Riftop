# Bolt's Journal

## 2025-05-18 - Derive Copy on FlowKey for Zero-Cost HashMap Lookups
**Learning:** `FlowKey` consists entirely of `Copy` fields (`IpAddr`, `u16`, `u8`). Without `Copy`, HashMap entry lookups in the packet ingestion hot path (`FlowTable::record` and `record_filtered`) called `.clone()` on every packet.
**Action:** Always derive `Copy` for small value structs in hot loops to allow zero-cost pass-by-value into HashMap entry and lookup routines without `.clone()`.
