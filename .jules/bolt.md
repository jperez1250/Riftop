# Bolt's Performance Journal - Critical Learnings Only

## 2025-02-18 - Pre-allocating HashMap capacity in top aggregation paths
**Learning:** Top aggregation functions (`top_hosts`, `top_ports`, `top_protocols`) aggregate snapshot flow records into temporary `HashMap` structures. Default `HashMap::new()` starts with 0 capacity and triggers multiple vector re-allocations and rehashes as flow numbers grow (up to 100,000 flows).
**Action:** Use `HashMap::with_capacity(snap.flows.len() * 2)` (for endpoints/ports) or `HashMap::with_capacity(snap.flows.len())` (for protocols) to eliminate rehashing during snapshot aggregation.
