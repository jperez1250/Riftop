# Bolt's Journal - Riftop Performance Learnings

## 2025-02-28 - Hot-Path Flow Table Record Allocation
**Learning:** `FlowTable::record` processes every incoming packet. Previously, `.entry(key.clone())` cloned `FlowKey` for every single packet, even when the key was already present in the map (which is true for >99.9% of packet records in an active stream).
**Action:** Deriving `Copy` on `FlowKey` and using `entry(key).or_insert_with_key(|k| FlowStats::new(*k, now))` avoids copying or cloning `FlowKey` when entries already exist in `FlowTable`. In addition, using `list.truncate(n)` instead of `.take(n).collect()` in `top_sorted` eliminates secondary vector allocations when producing top flow snapshots.
