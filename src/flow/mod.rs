//! Flow tracking and bandwidth accounting.

pub mod key;
pub mod rate;
pub mod stats;
pub mod table;

use std::time::Duration;

pub use key::{Aggregate, FlowKey};
pub use rate::RateWindow;
pub use stats::{Direction, FlowStats, TcpCounters};
pub use table::{FlowTable, Globals, Snapshot, SortBy};

#[must_use]
pub fn format_rate(bytes_per_sec: f64) -> String {
    format_rate_units(bytes_per_sec, false)
}

#[must_use]
pub fn format_rate_units(bytes_per_sec: f64, use_bytes: bool) -> String {
    if use_bytes {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut value = bytes_per_sec;
        let mut unit = 0;
        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }
        if value >= 100.0 {
            format!("{value:.0} {}/s", UNITS.get(unit).copied().unwrap_or(""))
        } else if value >= 10.0 {
            format!("{value:.1} {}/s", UNITS.get(unit).copied().unwrap_or(""))
        } else {
            format!("{value:.2} {}/s", UNITS.get(unit).copied().unwrap_or(""))
        }
    } else {
        const UNITS: &[&str] = &["b", "Kb", "Mb", "Gb", "Tb"];
        let mut value = bytes_per_sec * 8.0;
        let mut unit = 0;
        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }
        if value >= 100.0 {
            format!("{value:.0} {}", UNITS.get(unit).copied().unwrap_or(""))
        } else if value >= 10.0 {
            format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or(""))
        } else {
            format!("{value:.2} {}", UNITS.get(unit).copied().unwrap_or(""))
        }
    }
}

#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS.get(unit).copied().unwrap_or(""))
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or(""))
    } else {
        format!("{value:.2} {}", UNITS.get(unit).copied().unwrap_or(""))
    }
}

#[must_use]
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[must_use]
pub fn rate_bar(rate: f64, max_rate: f64, width: usize) -> String {
    if width == 0 || max_rate <= 0.0 || rate <= 0.0 {
        return " ".repeat(width);
    }
    let frac = (rate / max_rate).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let filled = ((frac * width as f64).round() as usize).min(width);
    format!("{}{}", "#".repeat(filled), " ".repeat(width - filled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    #[test]
    fn test_format_helpers() {
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m05s");
        assert_eq!(format_duration(Duration::from_secs(3665)), "1h01m");

        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(10_000), "9.77 KB");
        assert_eq!(format_bytes(10_000_000), "9.54 MB");

        assert_eq!(format_rate_units(100.0, true), "100 B/s");
        assert_eq!(format_rate_units(12500.0, false), "100 Kb");

        assert_eq!(rate_bar(50.0, 100.0, 10), "#####     ");
        assert_eq!(rate_bar(0.0, 100.0, 5), "     ");
        assert_eq!(rate_bar(50.0, 0.0, 5), "     ");
    }

    #[test]
    fn test_flow_key_symmetry_and_aggregation() {
        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let k1 = FlowKey::new(ip_a, ip_b, 1000, 2000, 6);
        let k2 = FlowKey::new(ip_b, ip_a, 2000, 1000, 6);
        assert_eq!(k1, k2);

        let k_src = FlowKey::aggregate(ip_a, ip_b, 1000, 2000, 6, Aggregate::Source, true);
        assert_eq!(k_src.a, ip_a);
        assert_eq!(k_src.b, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(k_src.port_a, 1000);
        assert_eq!(k_src.port_b, 0);

        let k_dst = FlowKey::aggregate(ip_a, ip_b, 1000, 2000, 6, Aggregate::Destination, false);
        assert_eq!(k_dst.a, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(k_dst.b, ip_b);
        assert_eq!(k_dst.port_a, 0);
        assert_eq!(k_dst.port_b, 0);

        let k_pair_noports = FlowKey::aggregate(ip_a, ip_b, 1000, 2000, 6, Aggregate::Pair, false);
        assert_eq!(k_pair_noports.port_a, 0);
        assert_eq!(k_pair_noports.port_b, 0);
        assert_eq!(k_pair_noports.protocol, 0);
    }

    #[test]
    fn test_rate_window_behavior() {
        let now = Instant::now();
        let mut window = RateWindow::new(Duration::from_secs(10));

        assert_eq!(window.rate(now), 0.0);

        window.add(now, 1000);
        // sample added within 100ms should coalesce
        window.add(now + Duration::from_millis(50), 500);
        assert_eq!(window.rate(now + Duration::from_millis(50)), 150.0); // 1500 bytes / 10s

        let future = now + Duration::from_secs(15);
        window.add(future, 2000);
        // previous sample at `now` is older than max_age (10s) and should be pruned
        assert_eq!(window.rate(future), 200.0); // 2000 bytes / 10s
    }

    #[test]
    fn test_tcp_counters() {
        let mut counters = TcpCounters::default();
        assert_eq!(counters.summary(), "");

        counters.observe(crate::protocols::TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            pure_ack: false,
            seq: 100,
            payload_len: 10,
        });
        assert_eq!(counters.summary(), "S1 F0 R0 A0 X0");

        // Retransmission observation
        counters.observe(crate::protocols::TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            pure_ack: false,
            seq: 100,
            payload_len: 10,
        });
        assert_eq!(counters.summary(), "S1 F0 R0 A0 X1");
    }

    #[test]
    fn test_flow_table_recording_and_sorting() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();

        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip_c: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Flow 1: A -> B
        table.record(ip_a, ip_b, 1234, 80, 6, 1000, &[ip_a], now, None);
        // Flow 2: C -> B
        table.record(ip_c, ip_b, 5678, 80, 6, 5000, &[ip_b], now, None);

        let globals = table.globals();
        assert_eq!(globals.packets_seen, 2);
        assert_eq!(globals.packets_accepted, 2);
        assert_eq!(globals.bytes_total, 6000);
        assert_eq!(globals.bytes_sent, 1000);
        assert_eq!(globals.bytes_recv, 5000);

        let top_total = table.top_sorted(10, now, SortBy::Total);
        assert_eq!(top_total.len(), 2);
        assert_eq!(top_total[0].total_bytes, 5000);

        let top_src = table.top_sorted(10, now, SortBy::Source);
        assert_eq!(top_src.len(), 2);

        assert_eq!(SortBy::parse("2s"), SortBy::Rate2s);
        assert_eq!(SortBy::parse("40s"), SortBy::Rate40s);
        assert_eq!(SortBy::parse("src"), SortBy::Source);
        assert_eq!(SortBy::parse("dst"), SortBy::Destination);
        assert_eq!(SortBy::parse("total"), SortBy::Total);
        assert_eq!(SortBy::parse("unknown"), SortBy::Rate10s);
    }

    #[test]
    fn test_flow_table_expiration() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(ip_a, ip_b, 100, 200, 6, 500, &[], now, None);
        assert_eq!(table.len(), 1);

        table.expire(now + Duration::from_secs(10), Duration::from_secs(30));
        assert_eq!(table.len(), 1);

        table.expire(now + Duration::from_secs(40), Duration::from_secs(30));
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }
}
