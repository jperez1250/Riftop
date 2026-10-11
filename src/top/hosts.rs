use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::flow::{FlowStats, Snapshot};
use crate::top::types::{rank, TopRow};

#[must_use]
pub fn top_hosts(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<IpAddr, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        accumulate_host(&mut map, s, now);
    }
    rank(map, n, |ip| ip.to_string())
}

fn accumulate_host(map: &mut HashMap<IpAddr, (u64, f64, f64, f64)>, s: &FlowStats, now: Instant) {
    let e_a = map.entry(s.key.a).or_insert((0, 0.0, 0.0, 0.0));
    e_a.0 += s.bytes_a_to_b;
    e_a.1 += s.rate_a_to_b_2s.rate(now);
    e_a.2 += s.rate_a_to_b_10s.rate(now);
    e_a.3 += s.rate_a_to_b_40s.rate(now);

    let e_b = map.entry(s.key.b).or_insert((0, 0.0, 0.0, 0.0));
    e_b.0 += s.bytes_b_to_a;
    e_b.1 += s.rate_b_to_a_2s.rate(now);
    e_b.2 += s.rate_b_to_a_10s.rate(now);
    e_b.3 += s.rate_b_to_a_40s.rate(now);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flow::{FlowTable, SortBy};

    #[test]
    fn test_top_hosts_aggregation() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        let src1: IpAddr = "10.0.0.1".parse().unwrap();
        let dst1: IpAddr = "10.0.0.2".parse().unwrap();
        let src2: IpAddr = "10.0.0.3".parse().unwrap();

        // 1000 bytes between 10.0.0.1 and 10.0.0.2
        table.record(src1, dst1, 80, 443, 6, 1000, &[], now, None);
        // 500 bytes between 10.0.0.1 and 10.0.0.3
        table.record(src1, src2, 80, 443, 6, 500, &[], now, None);

        let snap = table.snapshot_sorted(10, now, SortBy::Total);
        let rows = top_hosts(&snap, now, 5);

        assert!(!rows.is_empty());
        // 10.0.0.1 participated in both flows -> total 1500 bytes
        assert_eq!(rows[0].label, "10.0.0.1");
        assert_eq!(rows[0].bytes, 1500);
    }
}
