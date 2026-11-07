# Bloodhound's Journal

## 2026-11-07 - Top Ports Asymmetric Directional Accounting and Double Counting
**Issue:** `top_ports` in `src/top/ports.rs` incorrectly attributed only unidirectional flow bytes (`s.bytes_a_to_b` to `port_a` and `s.bytes_b_to_a` to `port_b`) rather than total flow volume (`s.total_bytes`). In network traffic monitoring, a port is a communication endpoint for the entire bidirectional flow; treating ports as strictly one-way caused inbound request traffic to be omitted from server ports and outbound response traffic to be omitted from client ports, while flows with identical ports (`port_a == port_b`) received both directions.
**Fix:** Updated `top_ports` to aggregate `s.total_bytes` and full window rates for both `port_a` and `port_b`, while explicitly guarding `s.key.port_b != s.key.port_a` to prevent double counting on same-port traffic.
**Prevention:** Accompany any endpoint/entity aggregation logic with tests checking bidirectional traffic flow and symmetric edge cases (such as source and destination sharing identical attributes).
