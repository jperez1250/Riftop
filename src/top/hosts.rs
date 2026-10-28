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
    use crate::flow::FlowTable;
    use std::net::Ipv4Addr;

    #[test]
    fn test_top_hosts_aggregation() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(ip1, ip2, 1000, 2000, 6, 500, &[ip1], now, None);

        let snap = table.snapshot(10, now);
        let hosts = top_hosts(&snap, now, 10);

        assert!(!hosts.is_empty());
        let h1 = hosts.iter().find(|h| h.label == "10.0.0.1");
        assert!(h1.is_some());
        assert_eq!(h1.unwrap().bytes, 500);
    }
}
