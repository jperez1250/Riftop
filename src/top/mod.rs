//! Aggregated TOP views: hosts, ports, protocols.

pub mod hosts;
pub mod ports;
pub mod protocols;
pub mod types;

pub use hosts::top_hosts;
pub use ports::top_ports;
pub use protocols::top_protocols;
pub use types::{format_top_row, TopRow, ViewMode};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flow::FlowTable;
    use std::time::Instant;

    #[test]
    fn test_top_aggregations_empty_snapshot() {
        let table = FlowTable::new();
        let now = Instant::now();
        let snap = table.snapshot(10, now);

        assert!(top_hosts(&snap, now, 10).is_empty());
        assert!(top_ports(&snap, now, 10).is_empty());
        assert!(top_protocols(&snap, now, 10).is_empty());
    }
}
