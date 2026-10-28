# Bolt's Journal - Critical Learnings

## 2025-05-18 - HashMap Pre-allocation and Avoided FlowKey Clones
**Learning:** In packet processing and snapshot aggregation, `FlowTable::record` entry lookup previously called `key.clone()` unconditionally on every incoming packet. Using `or_insert_with_key(|k| FlowStats::new(k.clone(), now))` avoids cloning `FlowKey` during hot-path lookups for existing flows. Additionally, pre-allocating `HashMap` capacity in `top_hosts`, `top_ports`, and `top_protocols` based on snapshot flow count eliminates multiple hash table reallocations during UI rendering.
**Action:** When performing `entry()` lookups in hot loops, use `or_insert_with_key` or pass owned keys directly instead of cloning upfront. Always pre-allocate hash map capacity using `HashMap::with_capacity` when collecting or aggregating over snapshots.
