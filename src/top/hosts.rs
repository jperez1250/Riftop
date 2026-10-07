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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, Globals};
    use std::str::FromStr;

    #[test]
    fn test_top_hosts_empty() {
        let snap = Snapshot {
            flows: vec![],
            globals: Globals::default(),
            taken_at: Instant::now(),
        };
        assert!(top_hosts(&snap, Instant::now(), 10).is_empty());
    }

    #[test]
    fn test_top_hosts_ranking() {
        let now = Instant::now();
        let ip1 = IpAddr::from_str("10.0.0.1").unwrap();
        let ip2 = IpAddr::from_str("10.0.0.2").unwrap();
        let key = FlowKey::new(ip1, ip2, 1234, 80, 6);

        let mut stats = FlowStats::new(key, now);
        stats.record_endpoints(now, ip1, 1234, 5000);

        let snap = Snapshot {
            flows: vec![stats],
            globals: Globals::default(),
            taken_at: now,
        };

        let top = top_hosts(&snap, now, 5);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].label, "10.0.0.1");
        assert_eq!(top[0].bytes, 5000);
    }
}
