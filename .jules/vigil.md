# Vigil's QA & Testing Journal

## 2025-05-18 - Flow Table Default Aggregation & Crate Lint Inheritance
**Challenge:** Unit testing `FlowTable` output formatting and export modules (`export.rs`) revealed that `FlowTable` defaults to host-level aggregation with port numbers zeroed (`sport=0`, `dport=0`) unless `table.set_show_ports(true)` is explicitly enabled. Furthermore, crate-level `#![deny(clippy::unwrap_used, clippy::expect_used)]` in `src/` applies to inner `#[cfg(test)] mod tests` unless explicitly overridden.
**Strategy:** In `#[cfg(test)] mod tests` inside `src/` modules, annotate the test module with `#[allow(clippy::unwrap_used, clippy::expect_used)]` for test assertion helpers. When asserting on port-specific flow exports or top-port metrics, ensure `table.set_show_ports(true)` is called prior to recording packet samples.
**Prevention:** Always verify default aggregate state when instantiating `FlowTable` in test harnesses, and enforce test lint overrides on inline `#[cfg(test)]` modules.
