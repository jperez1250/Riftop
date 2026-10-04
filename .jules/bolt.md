# Bolt's Journal - Critical Performance Learnings

## 2025-10-04 - Single-Pass Entry Map Lookups in Hot Packet Processing Loop
**Learning:** In high-throughput packet processing (`FlowTable::record` / `record_filtered`), using `contains_key(&key)` followed by `entry(key.clone())` causes double hashing and map lookups on every single packet, as well as unnecessary cloning of `FlowKey` for existing active flows.
**Action:** Use `match self.flows.entry(key)` directly. Check capacity/expiration limits inside the `Entry::Vacant` arm so occupied active flow lookups take the zero-clone, single-lookup fast path (`Entry::Occupied(e) => e.into_mut()`).
