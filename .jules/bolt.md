## 2025-05-18 - FlowKey Copy & or_insert_with_key in FlowTable Hot Path
**Learning:** `FlowKey` consisted only of `Copy` fields (`IpAddr`, `u16`, `u8`) but lacked a `Copy` derive. Furthermore, in `FlowTable::record` and `record_filtered`, `key.clone()` was passed to `.entry(key.clone())` so `key` could be moved into `or_insert_with(|| FlowStats::new(key, now))`.
**Action:** Derive `Copy` on `FlowKey` and use `or_insert_with_key(|k| FlowStats::new(*k, now))` with `.entry(key)` to completely eliminate key duplication on map lookups for existing flows.
