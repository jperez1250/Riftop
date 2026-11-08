# Bolt's Performance Journal

Critical performance learnings and architectural insights for Riftop.

## 2026-10-02 - Flow Table Entry & Top-Sorted Vec Allocation Elimination
**Learning:** In high-throughput packet processing loops (`FlowTable::record` and `record_filtered`), passing `key.clone()` to `HashMap::entry()` unconditionally clones the key on every single packet, even when the flow already exists. By moving `key` by value into `.entry(key)` and using `.or_insert_with_key(|k| FlowStats::new(k.clone(), now))`, key cloning is completely eliminated for existing flows. Additionally, in `FlowTable::top_sorted`, `list.into_iter().take(n).collect()` allocates a second vector heap buffer; using in-place `list.truncate(n)` reuses the already sorted buffer.
**Action:** When updating collections in packet hot paths, use `entry(key).or_insert_with_key(...)` to delay cloning keys until insertion is necessary, and use in-place mutations like `truncate()` instead of allocating fresh collections.
