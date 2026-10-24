# Vigil's Testing Journal & Critical Insights

## 2026-03-30 - Out-of-Order Timestamps & Duration Panics
**Challenge:** Network packet analysis and simulation loops often encounter out-of-order packet timestamps or time regressions during file processing or clock sync. Calling standard `Instant::duration_since` when `now < previous` causes a thread panic with "supplied instant is later than self".
**Strategy:** Guarded time difference calculations in stateful structures (`FlowTable::expire` and `AlertEngine::evaluate`) by using `now.saturating_duration_since(other)` and created edge-case unit tests asserting no panics occur when evaluating state with regressively earlier timestamps.
**Prevention:** Always use `Instant::saturating_duration_since` or `Instant::checked_sub` across flow tracking, snapshotting, and alert evaluation routines to guarantee resilience against non-monotonic or reordered timestamps.

## 2026-03-30 - Dual-Stack Link-Local Filtering Parity
**Challenge:** In network packet filter matching, ignoring link-local traffic (`allow_link_local = false`) could easily omit IPv4 link-local ranges (`169.254.0.0/16`) if only IPv6 link-local addresses (`fe80::/10`) are checked.
**Strategy:** Implemented explicit `is_link_local_v4` matching in `PacketFilter::accept` alongside `is_link_local_v6` and added comprehensive dual-stack integration regression tests in `tests/regression_filters.rs`.
**Prevention:** Ensure dual-stack protocol filtering logic explicitly exercises both IPv4 and IPv6 address types in boundary matrix tests.
