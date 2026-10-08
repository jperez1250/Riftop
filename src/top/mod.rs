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
mod tests {
    use super::*;
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    #[test]
    fn test_view_mode() {
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
        let now = Instant::now();
        let mut table = FlowTable::new();
        table.set_show_ports(true);

        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Record a TCP flow on port 80 (HTTP)
        table.record(ip_a, ip_b, 54321, 80, 6, 1000, &[ip_a], now, None);

        let snap = table.snapshot(10, now);

        // Test top hosts
        let hosts = top_hosts(&snap, now, 5);
        assert_eq!(hosts.len(), 2);
        assert!(hosts
            .iter()
            .any(|h| h.label == "192.168.1.100" && h.bytes == 1000));
        assert!(hosts.iter().any(|h| h.label == "10.0.0.1" && h.bytes == 0));

        // Test top ports
        let ports = top_ports(&snap, now, 5);
        assert_eq!(ports.len(), 2);
        assert!(ports.iter().any(|p| p.label.contains("80 (http)")));

        // Test top protocols
        let protos = top_protocols(&snap, now, 5);
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0].label, "TCP");
        assert_eq!(protos[0].bytes, 1000);

        // Test format_top_row
        let formatted = format_top_row(&protos[0]);
        assert_eq!(formatted.0, "TCP");
    }
}
