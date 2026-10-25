## 2026-03-30 - Derive Copy for FlowKey to optimize HashMap entry lookups

**Learning:** `FlowKey` consists entirely of `Copy` fields (`IpAddr`, `u16`, `u8`). Deriving `Copy` for `FlowKey` enables using `or_insert_with_key` in `HashMap::entry` during high-frequency packet recording (`FlowTable::record` and `record_filtered`).
**Action:** Avoid calling `.clone()` on map keys when `Copy` can be derived, and leverage `.or_insert_with_key(|&k| ...)` to eliminate redundant key copies when entries already exist in the map.
