//! Flow tracking and bandwidth accounting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::filters::PacketFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub a: IpAddr,
    pub b: IpAddr,
    pub port_a: u16,
    pub port_b: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, protocol: u8) -> Self {
        if (src, sport) <= (dst, dport) {
            Self {
                a: src,
                b: dst,
                port_a: sport,
                port_b: dport,
                protocol,
            }
        } else {
            Self {
                a: dst,
                b: src,
                port_a: dport,
                port_b: sport,
                protocol,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateWindow {
    samples: Vec<(Instant, u64)>,
    max_age: Duration,
}

impl RateWindow {
    pub fn new(max_age: Duration) -> Self {
        Self {
            samples: Vec::with_capacity(64),
            max_age,
        }
    }

    pub fn add(&mut self, now: Instant, bytes: u64) {
        self.samples.push((now, bytes));
        let cutoff = now - self.max_age;
        self.samples.retain(|(ts, _)| *ts >= cutoff);
    }

    pub fn rate(&self, now: Instant) -> f64 {
        let cutoff = now - self.max_age;
        let relevant: Vec<_> = self.samples.iter().filter(|(ts, _)| *ts >= cutoff).collect();
        if relevant.is_empty() {
            return 0.0;
        }
        let total: u64 = relevant.iter().map(|(_, b)| **b).sum();
        let first = relevant.first().map_or(now, |(t, _)| **t);
        let elapsed = now.duration_since(first).as_secs_f64().max(0.001);
        total as f64 / elapsed
    }
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub key: FlowKey,
    pub total_bytes: u64,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub rate_2s: RateWindow,
    pub rate_10s: RateWindow,
    pub rate_40s: RateWindow,
    pub last_seen: Instant,
}

impl FlowStats {
    pub fn new(key: FlowKey, now: Instant) -> Self {
        Self {
            key,
            total_bytes: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            rate_2s: RateWindow::new(Duration::from_secs(2)),
            rate_10s: RateWindow::new(Duration::from_secs(10)),
            rate_40s: RateWindow::new(Duration::from_secs(40)),
            last_seen: now,
        }
    }

    pub fn record(&mut self, now: Instant, bytes: u64, dir: Direction) {
        self.total_bytes += bytes;
        match dir {
            Direction::Sent => self.sent_bytes += bytes,
            Direction::Received => self.recv_bytes += bytes,
        }
        self.rate_2s.add(now, bytes);
        self.rate_10s.add(now, bytes);
        self.rate_40s.add(now, bytes);
        self.last_seen = now;
    }

    pub fn rate_2s(&self, now: Instant) -> f64 {
        self.rate_2s.rate(now)
    }
    pub fn rate_10s(&self, now: Instant) -> f64 {
        self.rate_10s.rate(now)
    }
    pub fn rate_40s(&self, now: Instant) -> f64 {
        self.rate_40s.rate(now)
    }
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        protocol: u8,
        bytes: u64,
        local_addrs: &[IpAddr],
        now: Instant,
    ) {
        let key = FlowKey::new(src, dst, sport, dport, protocol);
        let dir = if local_addrs.contains(&src) {
            Direction::Sent
        } else {
            Direction::Received
        };
        let entry = self
            .flows
            .entry(key.clone())
            .or_insert_with(|| FlowStats::new(key, now));
        entry.record(now, bytes, dir);
    }

    /// Apply packet filters then record. Returns false if dropped.
    pub fn record_filtered(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        protocol: u8,
        bytes: u64,
        local_addrs: &[IpAddr],
        now: Instant,
        filter: &PacketFilter,
    ) -> bool {
        if filter.net4.is_some() || filter.net6.is_some() || !filter.allow_link_local {
            match filter.accept(src, dst) {
                None => return false,
                Some(sent) if filter.has_net_filter(src) => {
                    let key = FlowKey::new(src, dst, sport, dport, protocol);
                    let dir = if sent {
                        Direction::Sent
                    } else {
                        Direction::Received
                    };
                    let entry = self
                        .flows
                        .entry(key.clone())
                        .or_insert_with(|| FlowStats::new(key, now));
                    entry.record(now, bytes, dir);
                    return true;
                }
                Some(_) => {}
            }
        }
        self.record(src, dst, sport, dport, protocol, bytes, local_addrs, now);
        true
    }

    pub fn top(&self, n: usize, now: Instant) -> Vec<&FlowStats> {
        let mut list: Vec<&FlowStats> = self.flows.values().collect();
        list.sort_by(|a, b| {
            b.rate_2s(now)
                .partial_cmp(&a.rate_2s(now))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        list.into_iter().take(n).collect()
    }

    pub fn expire(&mut self, now: Instant, max_idle: Duration) {
        self.flows
            .retain(|_, stats| now.duration_since(stats.last_seen) < max_idle);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

pub fn format_rate(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &["b", "Kb", "Mb", "Gb", "Tb"];
    let mut value = bytes_per_sec * 8.0;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn flow_key_is_canonical() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            FlowKey::new(a, b, 80, 443, 6),
            FlowKey::new(b, a, 443, 80, 6)
        );
    }
}
