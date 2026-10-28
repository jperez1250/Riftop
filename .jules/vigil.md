# Vigil QA Journal

## 2026-03-31 - Snapshot Top-Row Aggregation and Port Resolution Verification
**Challenge:** Testing `top_ports` and `top_protocols` required creating mock `Snapshot` instances with realistic `FlowStats` records. Without calling `table.set_show_ports(true)`, default host-level flow aggregation zeroes port numbers (`port_a = 0`, `port_b = 0`), which led to empty top port rows during test assertion.
**Strategy:** Configured `FlowTable::set_show_ports(true)` explicitly when setting up mock packet records in `FlowTable` before taking snapshots for `top_ports` and `top_protocols` testing.
**Prevention:** Always verify port-level aggregation flags when constructing synthetic flow tables or snapshots in test suites.
