use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::services::service_name;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        let flow_bytes = s.total_bytes;
        let r2 = s.rate_2s(now);
        let r10 = s.rate_10s(now);
        let r40 = s.rate_40s(now);

        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += flow_bytes;
            e_a.1 += r2;
            e_a.2 += r10;
            e_a.3 += r40;
        }
        if s.key.port_b != 0 && s.key.port_b != s.key.port_a {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += flow_bytes;
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
mod tests {
    use super::*;
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn test_top_ports_bidirectional_accounting() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // 100 bytes from port 12345 to port 80
        table.record(ip_a, ip_b, 12345, 80, 6, 100, &[ip_a], now, None);
        // 200 bytes from port 80 to port 12345
        table.record(ip_b, ip_a, 80, 12345, 6, 200, &[ip_a], now, None);

        let snap = table.snapshot(10, now);
        let ports = top_ports(&snap, now, 10);

        let port_80 = ports.iter().find(|p| p.label.starts_with("80"));
        let port_12345 = ports.iter().find(|p| p.label.starts_with("12345"));

        assert!(port_80.is_some(), "Port 80 should be present");
        assert!(port_12345.is_some(), "Port 12345 should be present");

        // Both port 80 and port 12345 participate in all 300 bytes of the flow
        assert_eq!(port_80.unwrap().bytes, 300);
        assert_eq!(port_12345.unwrap().bytes, 300);
    }
}
