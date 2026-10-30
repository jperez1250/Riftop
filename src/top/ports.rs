use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::services::service_name;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        let tot = s.total_bytes;
        let r2 = s.rate_2s(now);
        let r10 = s.rate_10s(now);
        let r40 = s.rate_40s(now);

        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += tot;
            e_a.1 += r2;
            e_a.2 += r10;
            e_a.3 += r40;
        }
        if s.key.port_b != 0 && s.key.port_b != s.key.port_a {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += tot;
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
    fn test_top_ports_bidirectional_and_equal_ports() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Flow 1: 10.0.0.1:12345 -> 10.0.0.2:80 (500 bytes A->B, 300 bytes B->A)
        table.record(a, b, 12345, 80, 6, 500, &[a], now, None);
        table.record(b, a, 80, 12345, 6, 300, &[a], now, None);

        // Flow 2: equal ports 80 -> 80
        table.record(a, b, 80, 80, 6, 200, &[a], now, None);

        let snap = table.snapshot(10, now);
        let ports = top_ports(&snap, now, 10);

        let port_80 = ports.iter().find(|p| p.label.starts_with("80")).unwrap();
        let port_12345 = ports.iter().find(|p| p.label.starts_with("12345")).unwrap();

        // Port 80 total: (500 + 300) from Flow 1 + 200 from Flow 2 = 1000 bytes
        assert_eq!(port_80.bytes, 1000);
        // Port 12345 total: (500 + 300) from Flow 1 = 800 bytes
        assert_eq!(port_12345.bytes, 800);
    }
}
