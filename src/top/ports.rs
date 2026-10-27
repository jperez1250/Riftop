use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::services::service_name;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::with_capacity(snap.flows.len());
    for s in &snap.flows {
        let total_bytes = s.total_bytes;
        let r2 = s.rate_2s(now);
        let r10 = s.rate_10s(now);
        let r40 = s.rate_40s(now);

        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += total_bytes;
            e_a.1 += r2;
            e_a.2 += r10;
            e_a.3 += r40;
        }
        if s.key.port_b != 0 && s.key.port_b != s.key.port_a {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += total_bytes;
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
    fn test_top_ports_bidirectional_and_same_port() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Flow 1: 10.0.0.1:12345 <-> 10.0.0.2:80
        // 500 bytes A -> B, 1000 bytes B -> A
        table.record(a, b, 12345, 80, 6, 500, &[a], now, None);
        table.record(b, a, 12345, 80, 6, 1000, &[a], now, None);

        // Flow 2: 10.0.0.1:53 <-> 10.0.0.2:53
        // 300 bytes A -> B, 200 bytes B -> A
        table.record(a, b, 53, 53, 17, 300, &[a], now, None);
        table.record(b, a, 53, 53, 17, 200, &[a], now, None);

        let snap = table.snapshot(10, now);
        let ports = top_ports(&snap, now, 10);

        let p80 = ports.iter().find(|p| p.label.starts_with("80")).unwrap();
        let p12345 = ports.iter().find(|p| p.label.starts_with("12345")).unwrap();
        let p53 = ports.iter().find(|p| p.label.starts_with("53")).unwrap();

        assert_eq!(p80.bytes, 1500);
        assert_eq!(p12345.bytes, 1500);
        assert_eq!(p53.bytes, 500);
    }
}
