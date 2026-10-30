# Bloodhound's Journal

## 2025-03-10 - Unidirectional Port Aggregation and Duration Panic Risks
**Issue:** `top_ports` in `src/top/ports.rs` accumulated unidirectional bytes (`bytes_a_to_b` for `port_a` and `bytes_b_to_a` for `port_b`) rather than total flow bytes (`s.total_bytes`), missing incoming response traffic on server/client ports. Additionally, calling `Duration::duration_since` in `FlowTable::expire` and `AlertEngine::evaluate` panicked when timestamps regressed or arrived out of order.
**Fix:** Updated `top_ports` to aggregate `s.total_bytes` and combined flow rates for both `port_a` and `port_b` (guarding against double counting when `port_a == port_b`), and replaced `.duration_since` with `.saturating_duration_since`.
**Prevention:** Always verify bidirectional flow attribution in port/protocol aggregations and use `saturating_duration_since` when computing time deltas from potentially non-monotonic packet timestamps or system clocks.
