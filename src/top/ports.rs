use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::services::service_name;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        let r2 = s.rate_2s(now);
        let r10 = s.rate_10s(now);
        let r40 = s.rate_40s(now);
        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += s.total_bytes;
            e_a.1 += r2;
            e_a.2 += r10;
            e_a.3 += r40;
        }
        if s.key.port_b != 0 && s.key.port_b != s.key.port_a {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += s.total_bytes;
            e_b.1 += r2;
            e_b.2 += r10;
            e_b.3 += r40;
        }
    }
    rank(map, n, |p| {
        service_name(p, 0).map_or_else(|| p.to_string(), |name| format!("{p} ({name})"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_top_ports_bidirectional_and_same_port_accounting() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Client (port 12345) sends 100 bytes to server (port 80)
        table.record(client, server, 12345, 80, 6, 100, &[client], now, None);
        // Server (port 80) replies with 900 bytes to client (port 12345)
        table.record(server, client, 80, 12345, 6, 900, &[client], now, None);

        let snap = table.snapshot(10, now);
        let ports = top_ports(&snap, now, 10);
        let port_80 = ports
            .iter()
            .find(|p| p.label.starts_with("80"))
            .expect("port 80 entry");
        let port_client = ports
            .iter()
            .find(|p| p.label.starts_with("12345"))
            .expect("port 12345 entry");

        // Both port 80 and port 12345 participated in the full 1000 byte flow
        assert_eq!(port_80.bytes, 1000);
        assert_eq!(port_client.bytes, 1000);

        // Same-port traffic (e.g. DNS port 53 to port 53) must not be double counted
        let mut same_port_table = FlowTable::new();
        same_port_table.set_show_ports(true);
        same_port_table.record(client, server, 53, 53, 17, 400, &[client], now, None);
        same_port_table.record(server, client, 53, 53, 17, 600, &[client], now, None);

        let same_snap = same_port_table.snapshot(10, now);
        let same_ports = top_ports(&same_snap, now, 10);
        let port_53 = same_ports
            .iter()
            .find(|p| p.label.starts_with("53"))
            .expect("port 53 entry");
        assert_eq!(port_53.bytes, 1000);
    }
}
