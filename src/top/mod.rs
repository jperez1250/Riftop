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
    use crate::flow::{FlowKey, FlowStats, Globals, Snapshot};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    #[test]
    fn test_top_aggregations() {
        let now = Instant::now();
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            50000,
            6,
        );
        let mut flow = FlowStats::new(key, now);
        flow.record_endpoints(now, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80, 500);
        flow.record(now, 500, crate::flow::Direction::Sent, None);

        let snap = Snapshot {
            flows: vec![flow],
            globals: Globals::default(),
            taken_at: now,
        };

        let hosts = top_hosts(&snap, now, 5);
        assert!(!hosts.is_empty());

        let ports = top_ports(&snap, now, 5);
        assert!(!ports.is_empty());

        let protos = top_protocols(&snap, now, 5);
        assert!(!protos.is_empty());

        let row_str = format_top_row(&hosts[0]);
        assert_eq!(row_str.0, "10.0.0.1");
        assert_eq!(hosts[0].bytes, 500);
    }
}
