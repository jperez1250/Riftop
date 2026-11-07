# Vigil's Testing Journal

## 2025-05-18 - Flow Key Canonicalization and Directional Port Accounting
**Challenge:** Testing `top_ports` and `top_protocols` requires understanding `FlowKey` canonicalization and `FlowStats::record_endpoints`. In Riftop, `FlowTable` defaults to host-level aggregation (`show_ports: false`), which collapses port numbers and protocols to 0 unless `table.set_show_ports(true)` is explicitly enabled. Furthermore, `top_ports` aggregates `bytes_a_to_b` for `port_a` and `bytes_b_to_a` for `port_b`.
**Strategy:** In automated tests targeting port and protocol aggregation, explicitly call `table.set_show_ports(true)`. Structure assertions with knowledge of `FlowKey::new` ordering `(src, sport) <= (dst, dport)` so that directional byte totals (`bytes_a_to_b` vs `bytes_b_to_a`) map correctly to `port_a` and `port_b`.
**Prevention:** Maintain integration tests that verify bidirectional traffic on canonicalized vs non-canonicalized flows to prevent regression in port accounting.
