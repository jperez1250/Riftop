# Bolt's Performance Journal

## 2026-11-06 - FlowTable Hot Path Key Cloning and Redundant Hash Lookups
**Learning:** `FlowTable::record` and `record_filtered` are executed on every captured packet. In the original implementation, `self.flows.contains_key(&key)` was evaluated unconditionally before checking capacity (`self.flows.len() >= MAX_FLOWS`), forcing a full hash lookup even though the flow table rarely reaches the 100k maximum limit. Additionally, calling `.entry(key.clone()).or_insert_with(...)` forced an unconditional clone of `FlowKey` for every single packet even when the flow already existed in the map.
**Action:** Reorder the condition to `self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key)` to eliminate redundant lookups on >99.9% of packets, and use `self.flows.entry(key).or_insert_with_key(|k| FlowStats::new(k.clone(), now))` so `key` is moved directly into `entry` and only cloned upon initial insertion of a new flow.
