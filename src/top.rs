//! Aggregated TOP views: hosts, ports, protocols.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crate::flow::{format_bytes, format_rate, FlowStats, Snapshot};
use crate::services::service_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    #[default]
    Flows,
    Hosts,
    Ports,
    Protocols,
}

impl ViewMode {
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Flows => "Top flows",
            Self::Hosts => "Top hosts",
            Self::Ports => "Top ports",
            Self::Protocols => "Top protocols",
        }
    }

    #[must_use]
    pub const fn cycle(self) -> Self {
        match self {
            Self::Flows => Self::Hosts,
            Self::Hosts => Self::Ports,
            Self::Ports => Self::Protocols,
            Self::Protocols => Self::Flows,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopRow {
    pub label: String,
    pub bytes: u64,
    pub rate_2s: f64,
    pub rate_10s: f64,
    pub rate_40s: f64,
}

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
    e_a.1 += s.rate_2s(now);
    e_a.2 += s.rate_10s(now);
    e_a.3 += s.rate_40s(now);

    let e_b = map.entry(s.key.b).or_insert((0, 0.0, 0.0, 0.0));
    e_b.0 += s.bytes_b_to_a;
    e_b.1 += s.rate_2s(now);
    e_b.2 += s.rate_10s(now);
    e_b.3 += s.rate_40s(now);
}

#[must_use]
pub fn top_ports(snap: &Snapshot, now: Instant, n: usize) -> Vec<TopRow> {
    let mut map: HashMap<u16, (u64, f64, f64, f64)> = HashMap::new();
    for s in &snap.flows {
        if s.key.port_a != 0 {
            let e_a = map.entry(s.key.port_a).or_insert((0, 0.0, 0.0, 0.0));
            e_a.0 += s.bytes_a_to_b;
            e_a.1 += s.rate_2s(now);
            e_a.2 += s.rate_10s(now);
            e_a.3 += s.rate_40s(now);
        }
        if s.key.port_b != 0 {
            let e_b = map.entry(s.key.port_b).or_insert((0, 0.0, 0.0, 0.0));
            e_b.0 += s.bytes_b_to_a;
            e_b.1 += s.rate_2s(now);
            e_b.2 += s.rate_10s(now);
            e_b.3 += s.rate_40s(now);
        }
    }
    rank(map, n, |p| {
        service_name(p, 0).map_or_else(|| p.to_string(), |name| format!("{p} ({name})"))
    })
}

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

fn rank<K, F>(map: HashMap<K, (u64, f64, f64, f64)>, n: usize, label: F) -> Vec<TopRow>
where
    F: Fn(K) -> String,
{
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    v.into_iter()
        .take(n)
        .map(|(k, (bytes, r2, r10, r40))| TopRow {
            label: label(k),
            bytes,
            rate_2s: r2,
            rate_10s: r10,
            rate_40s: r40,
        })
        .collect()
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

#[must_use]
pub fn format_top_row(row: &TopRow) -> (String, String, String, String, String) {
    (
        row.label.clone(),
        format_rate(row.rate_2s),
        format_rate(row.rate_10s),
        format_rate(row.rate_40s),
        format_bytes(row.bytes),
    )
}
