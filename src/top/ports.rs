use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::services::service_name;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += s.bytes_a_to_b;
            e_a.1 += s.rate_a_to_b_2s.rate(now);
            e_a.2 += s.rate_a_to_b_10s.rate(now);
            e_a.3 += s.rate_a_to_b_40s.rate(now);
        }
        if s.key.port_b != 0 {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += s.bytes_b_to_a;
            e_b.1 += s.rate_b_to_a_2s.rate(now);
            e_b.2 += s.rate_b_to_a_10s.rate(now);
            e_b.3 += s.rate_b_to_a_40s.rate(now);
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
    use crate::flow::{Direction, FlowKey, FlowStats, Globals};
    use std::net::IpAddr;

    #[test]
    fn test_top_ports_accounting() {
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().expect("valid ip");
        let ip_b: IpAddr = "10.0.0.2".parse().expect("valid ip");
        let key = FlowKey::new(ip_a, ip_b, 1234, 80, 6);

        let mut stats = FlowStats::new(key, now);
        stats.record_endpoints(now, ip_a, 1234, 500);
        stats.record(now, 500, Direction::Unknown, None);

        let snap = Snapshot {
            flows: vec![stats],
            globals: Globals::default(),
            taken_at: now,
        };

        let rows = top_ports(&snap, now, 10);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].label.contains("1234"));
        assert_eq!(rows[0].bytes, 500);
        assert!(rows[1].label.contains("80 (http)"));
        assert_eq!(rows[1].bytes, 0);
    }
}
