# Bolt's Performance Journal

## 2026-10-02 - Eliminate FlowKey cloning on packet ingestion hot path
**Learning:** In `FlowTable::record` and `FlowTable::record_filtered`, every single captured packet evaluated `self.flows.contains_key(&key)` even when `self.flows.len() < MAX_FLOWS`, and unconditionally cloned `key` via `self.flows.entry(key.clone())`. Moving `key` directly into `entry(key)` and using `or_insert_with_key(|k| FlowStats::new(k.clone(), now))` completely eliminates heap/data copying for `FlowKey` on all existing flows (which represents >99% of packets in steady-state network traffic). Furthermore, checking `self.flows.len() >= MAX_FLOWS` first allows short-circuiting the table lookup for capacity enforcement.
**Action:** When handling HashMap entries on high-throughput packet processing pipelines, always use `or_insert_with_key` to avoid pre-cloning keys, and verify table size bounds before querying keys.
