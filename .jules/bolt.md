# Bolt's Journal - Critical Performance Learnings

## 2025-05-18 - Eliminating Redundant Lookups and Clones in Packet Ingestion

**Learning:** In Riftop, `FlowTable::record` and `FlowTable::record_filtered` are executed on every single captured packet (often tens to hundreds of thousands of times per second). Two avoidable bottlenecks existed on this critical hot path:
1. `!self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS`: Evaluating `contains_key(&key)` first caused a full hash computation and bucket lookup on every single incoming packet, even though `self.flows.len() >= MAX_FLOWS` is almost never true during normal operation. Flipping the check to evaluate table capacity first avoids hashing and map search completely.
2. `self.flows.entry(key.clone()).or_insert_with(|| FlowStats::new(key, now))`: Cloning `key` unconditionally before checking `entry` caused a clone on every single packet, even when the flow already existed. Using `self.flows.entry(key).or_insert_with_key(|k| FlowStats::new(k.clone(), now))` moves the key directly into `entry` and only clones `key` once when inserting a brand-new flow.
3. In `FlowTable::top_sorted`, `list.into_iter().take(n).collect()` allocated a new `Vec` after sorting. Truncating in-place with `list.truncate(n)` reuses the allocated vector buffer with zero extra heap allocations.

**Action:** On hot ingestion and aggregation paths, always check cheap numeric limits before hashing/lookups, leverage `Entry::or_insert_with_key` to avoid speculative `.clone()`s, and reuse allocated vectors using `.truncate()`.
