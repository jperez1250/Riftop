use std::collections::HashMap;
use std::time::Instant;

use crate::flow::Snapshot;
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_protocols(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u8, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        let e = map.entry(s.key.protocol).or_insert((0, 0.0, 0.0, 0.0));
        e.0 += s.total_bytes;
        e.1 += s.rate_2s(now);
        e.2 += s.rate_10s(now);
        e.3 += s.rate_40s(now);
    }
    rank(map, n, |p| proto_name(p).to_string())
}

const fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        0 => "any",
        _ => "other",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flow::{Direction, FlowKey, FlowStats, Globals};
    use std::net::IpAddr;

    #[test]
    fn test_top_protocols_accounting() {
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().expect("valid ip");
        let ip_b: IpAddr = "10.0.0.2".parse().expect("valid ip");
        let key_tcp = FlowKey::new(ip_a, ip_b, 1234, 80, 6);
        let key_udp = FlowKey::new(ip_a, ip_b, 1234, 53, 17);

        let mut stats_tcp = FlowStats::new(key_tcp, now);
        stats_tcp.record(now, 1000, Direction::Unknown, None);

        let mut stats_udp = FlowStats::new(key_udp, now);
        stats_udp.record(now, 500, Direction::Unknown, None);

        let snap = Snapshot {
            flows: vec![stats_tcp, stats_udp],
            globals: Globals::default(),
            taken_at: now,
        };

        let rows = top_protocols(&snap, now, 10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].label, "TCP");
        assert_eq!(rows[0].bytes, 1000);
        assert_eq!(rows[1].label, "UDP");
        assert_eq!(rows[1].bytes, 500);
    }
}
