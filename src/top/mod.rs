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
    use crate::flow::{FlowTable, SortBy};
    use std::net::IpAddr;
    use std::time::Instant;

    #[test]
    fn test_top_hosts_ports_protocols_aggregation() {
        let mut table = FlowTable::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Instant::now();

        table.set_show_ports(true);
        // Record TCP HTTP flow (port 80)
        table.record(ip1, ip2, 12345, 80, 6, 1000, &[ip1], now, None);
        // Record UDP DNS flow (port 53)
        table.record(ip1, ip2, 54321, 53, 17, 500, &[ip1], now, None);

        let snap = table.snapshot_sorted(10, now, SortBy::Total);

        // Top Hosts
        let hosts = top_hosts(&snap, now, 10);
        assert_eq!(hosts.len(), 2);
        // Top host by total bytes
        assert!(hosts
            .iter()
            .any(|h| h.label == "10.0.0.1" && h.bytes == 1500));
        assert!(hosts.iter().any(|h| h.label == "10.0.0.2" && h.bytes == 0));

        // Top Ports
        let ports = top_ports(&snap, now, 10);
        assert!(ports.iter().any(|p| p.label.contains("80 (http)")));
        assert!(ports.iter().any(|p| p.label.contains("53 (domain)")));

        // Top Protocols
        let protos = top_protocols(&snap, now, 10);
        assert!(protos
            .iter()
            .any(|pr| pr.label == "TCP" && pr.bytes == 1000));
        assert!(protos.iter().any(|pr| pr.label == "UDP" && pr.bytes == 500));
    }
}
