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
    use crate::flow::{FlowTable, SortBy};
    use std::net::{IpAddr, Ipv4Addr};
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
    fn test_format_top_row() {
        let row = TopRow {
            label: "10.0.0.1".to_string(),
            bytes: 1024,
            rate_2s: 100.0,
            rate_10s: 200.0,
            rate_40s: 300.0,
        };
        let (lbl, r2, r10, r40, b) = format_top_row(&row);
        assert_eq!(lbl, "10.0.0.1");
        assert_eq!(b, "1.00 KB");
        assert!(!r2.is_empty());
        assert!(!r10.is_empty());
        assert!(!r40.is_empty());
    }

    #[test]
    fn test_top_aggregations() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();

        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // TCP flow on port 80 (HTTP)
        table.record(ip_a, ip_b, 1234, 80, 6, 5000, &[ip_a], now, None);
        // UDP flow on port 53 (DNS)
        table.record(ip_a, ip_b, 5678, 53, 17, 2000, &[ip_a], now, None);

        let snap = table.snapshot_sorted(10, now, SortBy::Rate10s);

        // Top Hosts
        let hosts = top_hosts(&snap, now, 5);
        assert_eq!(hosts.len(), 2);

        // Top Ports
        let ports = top_ports(&snap, now, 5);
        assert!(!ports.is_empty());
        assert!(ports
            .iter()
            .any(|p| p.label.contains("80") || p.label.contains("http")));

        // Top Protocols
        let protos = top_protocols(&snap, now, 5);
        assert_eq!(protos.len(), 2);
        assert_eq!(protos[0].label, "TCP"); // 5000 bytes > 2000 bytes
        assert_eq!(protos[1].label, "UDP");
    }
}
