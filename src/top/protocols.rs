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
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_top_protocols_aggregation() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(ip1, ip2, 1000, 80, 6, 600, &[ip1], now, None); // TCP
        table.record(ip1, ip2, 1000, 53, 17, 300, &[ip1], now, None); // UDP

        let snap = table.snapshot(10, now);
        let protos = top_protocols(&snap, now, 10);

        assert_eq!(protos.len(), 2);
        assert_eq!(protos[0].label, "TCP");
        assert_eq!(protos[0].bytes, 600);
        assert_eq!(protos[1].label, "UDP");
        assert_eq!(protos[1].bytes, 300);
    }
}
