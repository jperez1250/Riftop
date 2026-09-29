//! Flow tracking and bandwidth accounting.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::filters::PacketFilter;
use crate::protocols::TcpFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Aggregate {
    #[default]
    Pair,
    Source,
    Destination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortBy {
    Rate2s,
    #[default]
    Rate10s,
    Rate40s,
    Source,
    Destination,
    Total,
}

impl SortBy {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "2s" => Self::Rate2s,
            "40s" => Self::Rate40s,
            "source" | "src" => Self::Source,
            "destination" | "dst" => Self::Destination,
            "total" => Self::Total,
            _ => Self::Rate10s,
        }
    }
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
            Self { a: src, b: dst, port_a: sport, port_b: dport, protocol }
        } else {
            Self { a: dst, b: src, port_a: dport, port_b: sport, protocol }
        }
    }

    pub fn aggregate(
        src: IpAddr, dst: IpAddr, sport: u16, dport: u16, protocol: u8,
        mode: Aggregate, show_ports: bool,
    ) -> Self {
        match mode {
            Aggregate::Source => Self {
                a: src, b: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port_a: if show_ports { sport } else { 0 }, port_b: 0,
                protocol: if show_ports { protocol } else { 0 },
            },
            Aggregate::Destination => Self {
                a: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), b: dst,
                port_a: 0, port_b: if show_ports { dport } else { 0 },
                protocol: if show_ports { protocol } else { 0 },
            },
            Aggregate::Pair if show_ports => Self::new(src, dst, sport, dport, protocol),
            Aggregate::Pair => Self::new(src, dst, 0, 0, 0),
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
        Self { samples: Vec::with_capacity(64), max_age }
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

#[derive(Debug, Clone, Default)]
pub struct TcpCounters {
    pub syn: u64,
    pub fin: u64,
    pub rst: u64,
    pub pure_ack: u64,
    pub retrans: u64,
    last_data_seq: Option<u32>,
}

impl TcpCounters {
    pub fn observe(&mut self, flags: TcpFlags) {
        if flags.syn { self.syn += 1; }
        if flags.fin { self.fin += 1; }
        if flags.rst { self.rst += 1; }
        if flags.pure_ack { self.pure_ack += 1; }
        if flags.payload_len > 0 {
            if self.last_data_seq == Some(flags.seq) {
                self.retrans += 1;
            }
            self.last_data_seq = Some(flags.seq);
        }
    }

    pub fn summary(&self) -> String {
        if self.syn == 0 && self.fin == 0 && self.rst == 0 && self.pure_ack == 0 && self.retrans == 0 {
            return String::new();
        }
        format!("S{} F{} R{} A{} X{}", self.syn, self.fin, self.rst, self.pure_ack, self.retrans)
    }
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub key: FlowKey,
    pub total_bytes: u64,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub packets: u64,
    pub tcp: TcpCounters,
    pub rate_2s: RateWindow,
    pub rate_10s: RateWindow,
    pub rate_40s: RateWindow,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl FlowStats {
    pub fn new(key: FlowKey, now: Instant) -> Self {
        Self {
            key, total_bytes: 0, sent_bytes: 0, recv_bytes: 0, packets: 0,
            tcp: TcpCounters::default(),
            rate_2s: RateWindow::new(Duration::from_secs(2)),
            rate_10s: RateWindow::new(Duration::from_secs(10)),
            rate_40s: RateWindow::new(Duration::from_secs(40)),
            first_seen: now, last_seen: now,
        }
    }

    pub fn record(&mut self, now: Instant, bytes: u64, dir: Direction, tcp: Option<TcpFlags>) {
        self.total_bytes += bytes;
        self.packets += 1;
        match dir {
            Direction::Sent => self.sent_bytes += bytes,
            Direction::Received => self.recv_bytes += bytes,
        }
        if let Some(f) = tcp { self.tcp.observe(f); }
        self.rate_2s.add(now, bytes);
        self.rate_10s.add(now, bytes);
        self.rate_40s.add(now, bytes);
        self.last_seen = now;
    }

    pub fn duration(&self) -> Duration {
        self.last_seen.saturating_duration_since(self.first_seen)
    }

    pub fn rate_2s(&self, now: Instant) -> f64 { self.rate_2s.rate(now) }
    pub fn rate_10s(&self, now: Instant) -> f64 { self.rate_10s.rate(now) }
    pub fn rate_40s(&self, now: Instant) -> f64 { self.rate_40s.rate(now) }
}

#[derive(Debug, Clone, Default)]
pub struct Globals {
    pub packets_seen: u64,
    pub packets_accepted: u64,
    pub bytes_total: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub flows: Vec<FlowStats>,
    pub globals: Globals,
    pub taken_at: Instant,
}

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowStats>,
    globals: Globals,
    aggregate: Aggregate,
    show_ports: bool,
}

fn rate_ord(a: f64, b: f64) -> Ordering {
    b.partial_cmp(&a).unwrap_or(Ordering::Equal)
}

impl FlowTable {
    pub fn new() -> Self { Self::default() }

    pub fn set_aggregate(&mut self, mode: Aggregate) { self.aggregate = mode; }
    pub fn set_show_ports(&mut self, show: bool) { self.show_ports = show; }
    pub fn globals(&self) -> Globals { self.globals.clone() }

    pub fn record(
        &mut self, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, protocol: u8,
        bytes: u64, local_addrs: &[IpAddr], now: Instant, tcp: Option<TcpFlags>,
    ) {
        self.globals.packets_seen += 1;
        self.globals.packets_accepted += 1;
        self.globals.bytes_total += bytes;
        let key = FlowKey::aggregate(src, dst, sport, dport, protocol, self.aggregate, self.show_ports);
        let dir = if local_addrs.contains(&src) { Direction::Sent } else { Direction::Received };
        match dir {
            Direction::Sent => self.globals.bytes_sent += bytes,
            Direction::Received => self.globals.bytes_recv += bytes,
        }
        let entry = self.flows.entry(key.clone()).or_insert_with(|| FlowStats::new(key, now));
        entry.record(now, bytes, dir, tcp);
    }

    pub fn record_filtered(
        &mut self, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, protocol: u8,
        bytes: u64, local_addrs: &[IpAddr], now: Instant, filter: &PacketFilter,
        tcp: Option<TcpFlags>,
    ) -> bool {
        self.globals.packets_seen += 1;
        if filter.net4.is_some() || filter.net6.is_some() || !filter.allow_link_local {
            match filter.accept(src, dst) {
                None => return false,
                Some(sent) if filter.has_net_filter(src) => {
                    self.globals.packets_accepted += 1;
                    self.globals.bytes_total += bytes;
                    let key = FlowKey::aggregate(src, dst, sport, dport, protocol, self.aggregate, self.show_ports);
                    let dir = if sent { Direction::Sent } else { Direction::Received };
                    match dir {
                        Direction::Sent => self.globals.bytes_sent += bytes,
                        Direction::Received => self.globals.bytes_recv += bytes,
                    }
                    let entry = self.flows.entry(key.clone()).or_insert_with(|| FlowStats::new(key, now));
                    entry.record(now, bytes, dir, tcp);
                    return true;
                }
                Some(_) => {}
            }
        }
        self.record(src, dst, sport, dport, protocol, bytes, local_addrs, now, tcp);
        true
    }

    pub fn top(&self, n: usize, now: Instant) -> Vec<&FlowStats> {
        self.top_sorted(n, now, SortBy::Rate2s)
    }

    pub fn top_sorted(&self, n: usize, now: Instant, sort: SortBy) -> Vec<&FlowStats> {
        let mut list: Vec<&FlowStats> = self.flows.values().collect();
        list.sort_by(|a, b| match sort {
            SortBy::Rate2s => rate_ord(a.rate_2s(now), b.rate_2s(now)),
            SortBy::Rate10s => rate_ord(a.rate_10s(now), b.rate_10s(now)),
            SortBy::Rate40s => rate_ord(a.rate_40s(now), b.rate_40s(now)),
            SortBy::Total => b.total_bytes.cmp(&a.total_bytes),
            SortBy::Source => a.key.a.cmp(&b.key.a),
            SortBy::Destination => a.key.b.cmp(&b.key.b),
        });
        list.into_iter().take(n).collect()
    }

    pub fn snapshot(&self, n: usize, now: Instant) -> Snapshot {
        self.snapshot_sorted(n, now, SortBy::Rate2s)
    }

    pub fn snapshot_sorted(&self, n: usize, now: Instant, sort: SortBy) -> Snapshot {
        Snapshot {
            flows: self.top_sorted(n, now, sort).into_iter().cloned().collect(),
            globals: self.globals.clone(),
            taken_at: now,
        }
    }

    pub fn expire(&mut self, now: Instant, max_idle: Duration) {
        self.flows.retain(|_, s| now.duration_since(s.last_seen) < max_idle);
    }

    pub fn len(&self) -> usize { self.flows.len() }
    pub fn is_empty(&self) -> bool { self.flows.is_empty() }
}

pub fn format_rate(bytes_per_sec: f64) -> String {
    format_rate_units(bytes_per_sec, false)
}

pub fn format_rate_units(bytes_per_sec: f64, use_bytes: bool) -> String {
    if use_bytes {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut value = bytes_per_sec;
        let mut unit = 0;
        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }
        if value >= 100.0 { format!("{value:.0} {}/s", UNITS[unit]) }
        else if value >= 10.0 { format!("{value:.1} {}/s", UNITS[unit]) }
        else { format!("{value:.2} {}/s", UNITS[unit]) }
    } else {
        const UNITS: &[&str] = &["b", "Kb", "Mb", "Gb", "Tb"];
        let mut value = bytes_per_sec * 8.0;
        let mut unit = 0;
        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }
        if value >= 100.0 { format!("{value:.0} {}", UNITS[unit]) }
        else if value >= 10.0 { format!("{value:.1} {}", UNITS[unit]) }
        else { format!("{value:.2} {}", UNITS[unit]) }
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
    if value >= 100.0 { format!("{value:.0} {}", UNITS[unit]) }
    else if value >= 10.0 { format!("{value:.1} {}", UNITS[unit]) }
    else { format!("{value:.2} {}", UNITS[unit]) }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 { format!("{secs}s") }
    else if secs < 3600 { format!("{}m{:02}s", secs / 60, secs % 60) }
    else { format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60) }
}

pub fn rate_bar(rate: f64, max_rate: f64, width: usize) -> String {
    if width == 0 || max_rate <= 0.0 || rate <= 0.0 {
        return " ".repeat(width);
    }
    let frac = (rate / max_rate).clamp(0.0, 1.0);
    let filled = ((frac * width as f64).round() as usize).min(width);
    format!("{}{}", "#".repeat(filled), " ".repeat(width - filled))
}
