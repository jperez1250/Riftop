## 2025-02-23 - Eliminate Key Cloning and Vector Allocations in Flow Table
**Learning:** `FlowTable::record` was cloning `FlowKey` before querying `HashMap::entry()`, causing an unnecessary clone/allocation on every packet recorded even when the flow entry already existed. Additionally, `FlowTable::top_sorted` was doing `list.into_iter().take(n).collect()`, allocating a second `Vec` when returning sorted top flows.
**Action:** Implement `Copy` on `FlowKey` and use `or_insert_with_key` for map lookups, and `list.truncate(n)` for in-place vector size limiting.
