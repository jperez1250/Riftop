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
    use std::net::IpAddr;
    use std::time::Instant;

    #[test]
    fn test_view_mode_cycle_and_title() {
        assert_eq!(ViewMode::Flows.title(), "Top flows");
        assert_eq!(ViewMode::Hosts.title(), "Top hosts");
        assert_eq!(ViewMode::Ports.title(), "Top ports");
        assert_eq!(ViewMode::Protocols.title(), "Top protocols");

        assert_eq!(ViewMode::Flows.cycle(), ViewMode::Hosts);
        assert_eq!(ViewMode::Hosts.cycle(), ViewMode::Ports);
        assert_eq!(ViewMode::Ports.cycle(), ViewMode::Protocols);
        assert_eq!(ViewMode::Protocols.cycle(), ViewMode::Flows);
    }

    #[test]
    fn test_top_aggregations() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        table.record(ip_a, ip_b, 443, 50000, 6, 1000, &[ip_a], now, None);
        table.record(ip_a, ip_b, 80, 50001, 6, 500, &[ip_a], now, None);

        let snap = table.snapshot(10, now);

        let hosts = top_hosts(&snap, now, 5);
        assert!(!hosts.is_empty());
        assert_eq!(hosts[0].label, "10.0.0.1");
        assert_eq!(hosts[0].bytes, 1500);

        let ports = top_ports(&snap, now, 5);
        assert!(!ports.is_empty());

        let protos = top_protocols(&snap, now, 5);
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0].label, "TCP");
        assert_eq!(protos[0].bytes, 1500);
    }
}
