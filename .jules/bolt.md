# Bolt's Journal - Performance Insights & Critical Learnings

## 2025-02-18 - Deriving Copy for FlowKey Eliminates Hot-Path Clones
**Learning:** `FlowKey` consists solely of `Copy` fields (`IpAddr`, `u16`, `u8`). Deriving `Copy` on `FlowKey` enables bitwise pass-by-value and eliminates calls to `.clone()` in `FlowTable::record` and `FlowTable::record_filtered` during packet ingestion.
**Action:** Always derive `Copy` on pure value structs in packet processing hot paths to avoid unnecessary `.clone()` allocations and method calls on every packet.
