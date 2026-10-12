# Bolt's Journal - Critical Learnings

## 2025-05-18 - Deriving Copy for FlowKey & HashMap entry optimization
**Learning:** `FlowKey` only contains `Copy` fields (`IpAddr`, `u16`, `u8`). Deriving `Copy` and using `self.flows.entry(key).or_insert_with_key(...)` in `FlowTable::record` eliminates redundant key cloning for every packet processed in the hot capture loop.
**Action:** When updating hash map entries in packet ingestion paths, ensure the key implements `Copy` if all inner types are `Copy` and defer value construction using `or_insert_with_key`.
