## 2025-05-18 - Copy FlowKey and Avoid HashMap Key Cloning in Flow Table

**Learning:** `FlowKey` only contains primitive types (`IpAddr`, `u16`, `u8`) which all implement `Copy`. Deriving `Copy` on `FlowKey` allows passing it by value into `HashMap::entry(key)`. Combining this with `entry(key).or_insert_with_key(|&k| FlowStats::new(k, now))` avoids calling `.clone()` on every packet in `FlowTable::record` and `FlowTable::record_filtered`.
**Action:** When working on hash map lookup paths for small structs, derive `Copy` if all inner types are `Copy` and use `or_insert_with_key` to avoid unneeded allocation or cloning on map hits in hot packet processing loops.
