# Bolt's Journal - Critical Performance Learnings

## 2025-10-04 - Single-Lookup Fast Path in Hot Packet Processing Loop
**Learning:** In high-throughput packet processing (`FlowTable::record` / `record_filtered`), using `contains_key(&key)` followed by `entry(key.clone())` causes double hashing and map lookups on every single packet, as well as unnecessary cloning of `FlowKey` for existing active flows. Returning references across an `if/else` block extends the mutable borrow in Rust's borrow checker.
**Action:** Use `if let Some(entry) = self.flows.get_mut(&key)` with an early return for existing flows (>99.9% of packets). This isolates the mutable borrow scope and allows fallback capacity checks and `entry(key)` insertion without borrow conflicts.
