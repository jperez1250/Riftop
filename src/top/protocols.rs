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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, FlowStats, Globals};
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_proto_names() {
        assert_eq!(proto_name(1), "ICMP");
        assert_eq!(proto_name(6), "TCP");
        assert_eq!(proto_name(17), "UDP");
        assert_eq!(proto_name(58), "ICMPv6");
        assert_eq!(proto_name(0), "any");
        assert_eq!(proto_name(99), "other");
    }

    #[test]
    fn test_top_protocols_ranking() {
        let now = Instant::now();
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let key_tcp = FlowKey::new(ip1, ip2, 80, 12345, 6);
        let key_udp = FlowKey::new(ip1, ip2, 53, 54321, 17);

        let mut stats_tcp = FlowStats::new(key_tcp, now);
        stats_tcp.record(now, 10000, crate::flow::Direction::Sent, None);

        let mut stats_udp = FlowStats::new(key_udp, now);
        stats_udp.record(now, 2000, crate::flow::Direction::Sent, None);

        let snap = Snapshot {
            flows: vec![stats_tcp, stats_udp],
            globals: Globals::default(),
            taken_at: now,
        };

        let top = top_protocols(&snap, now, 5);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].label, "TCP");
        assert_eq!(top[0].bytes, 10000);
        assert_eq!(top[1].label, "UDP");
        assert_eq!(top[1].bytes, 2000);
    }
}
