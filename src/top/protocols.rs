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
    use crate::flow::{FlowTable, SortBy};
    use std::net::IpAddr;

    #[test]
    fn test_top_protocols_aggregation() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();

        table.record(src, dst, 80, 443, 6, 1200, &[], now, None); // TCP
        table.record(src, dst, 53, 53, 17, 300, &[], now, None); // UDP

        let snap = table.snapshot_sorted(10, now, SortBy::Total);
        let rows = top_protocols(&snap, now, 5);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].label, "TCP");
        assert_eq!(rows[0].bytes, 1200);
        assert_eq!(rows[1].label, "UDP");
        assert_eq!(rows[1].bytes, 300);
    }
}
