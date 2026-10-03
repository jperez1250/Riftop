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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn test_format_rate_units_bits_and_bytes() {
        assert_eq!(format_rate_units(0.0, false), "0.00 b");
        assert_eq!(format_rate_units(0.0, true), "0.00 B/s");

        // 125 bytes/sec = 1000 bits/sec = 1.00 Kb
        assert_eq!(format_rate_units(125.0, false), "1.00 Kb");
        assert_eq!(format_rate_units(1000.0, true), "1.00 KB/s");

        // High values
        assert_eq!(format_rate_units(100_000_000.0, false), "800 Mb");
        assert_eq!(format_rate_units(100_000_000.0, true), "100 MB/s");
    }

    #[test]
    fn test_format_bytes_boundaries() {
        assert_eq!(format_bytes(0), "0.00 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(10 * 1024), "10.0 KB");
        assert_eq!(format_bytes(100 * 1024), "100 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 1024), "1.00 TB");
    }

    #[test]
    fn test_format_duration_variants() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m00s");
        assert_eq!(format_duration(Duration::from_secs(3665)), "1h01m");
    }

    #[test]
    fn test_rate_bar_rendering() {
        assert_eq!(rate_bar(10.0, 100.0, 0), "");
        assert_eq!(rate_bar(0.0, 100.0, 10), "          ");
        assert_eq!(rate_bar(50.0, 100.0, 10), "#####     ");
        assert_eq!(rate_bar(100.0, 100.0, 10), "##########");
        assert_eq!(rate_bar(150.0, 100.0, 10), "##########"); // Clamped
        assert_eq!(rate_bar(50.0, -10.0, 10), "          "); // Invalid max
    }

    #[test]
    fn test_flow_key_canonical_ordering_and_aggregation() {
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Direct ordering
        let k1 = FlowKey::new(ip1, ip2, 80, 443, 6);
        assert_eq!(k1.a, ip1);
        assert_eq!(k1.b, ip2);
        assert_eq!(k1.port_a, 80);
        assert_eq!(k1.port_b, 443);

        // Swapped ordering (ip2 > ip1)
        let k2 = FlowKey::new(ip2, ip1, 443, 80, 6);
        assert_eq!(k2.a, ip1);
        assert_eq!(k2.b, ip2);
        assert_eq!(k2.port_a, 80);
        assert_eq!(k2.port_b, 443);
        assert_eq!(k1, k2);

        // Aggregation modes
        let k_src = FlowKey::aggregate(ip1, ip2, 80, 443, 6, Aggregate::Source, true);
        assert_eq!(k_src.a, ip1);
        assert_eq!(k_src.b, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(k_src.port_a, 80);
        assert_eq!(k_src.port_b, 0);

        let k_dst = FlowKey::aggregate(ip1, ip2, 80, 443, 6, Aggregate::Destination, false);
        assert_eq!(k_dst.a, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(k_dst.b, ip2);
        assert_eq!(k_dst.port_a, 0);
        assert_eq!(k_dst.port_b, 0);
    }

    #[test]
    fn test_rate_window_aggregation_and_pruning() {
        let mut rw = RateWindow::new(Duration::from_secs(2));
        let now = Instant::now();

        assert_eq!(rw.rate(now), 0.0);

        // Add 100 bytes at now
        rw.add(now, 100);
        // Add 100 bytes 50ms later (should sub-aggregate into same sample slot < 100ms)
        rw.add(now + Duration::from_millis(50), 100);

        assert_eq!(rw.rate(now + Duration::from_millis(50)), 200.0 / 2.0);

        // Add 200 bytes 1 second later
        rw.add(now + Duration::from_secs(1), 200);
        assert_eq!(rw.rate(now + Duration::from_secs(1)), 400.0 / 2.0);

        // Rate at 3 seconds (sample at `now` should be pruned)
        let future = now + Duration::from_secs(3);
        assert_eq!(rw.rate(future), 200.0 / 2.0);

        // Rate at 5 seconds (all samples pruned)
        let far_future = now + Duration::from_secs(5);
        assert_eq!(rw.rate(far_future), 0.0);
    }

    #[test]
    fn test_tcp_counters_and_flow_stats() {
        let mut tcp = TcpCounters::default();
        assert_eq!(tcp.summary(), "");

        tcp.observe(crate::protocols::TcpFlags {
            syn: true,
            fin: false,
            rst: false,
            ack: false,
            psh: false,
            pure_ack: false,
            seq: 100,
            payload_len: 0,
        });
        assert_eq!(tcp.summary(), "S1 F0 R0 A0 X0");

        tcp.observe(crate::protocols::TcpFlags {
            syn: false,
            fin: false,
            rst: false,
            ack: true,
            psh: false,
            pure_ack: false,
            seq: 200,
            payload_len: 10,
        });
        // Retransmission observation
        tcp.observe(crate::protocols::TcpFlags {
            syn: false,
            fin: false,
            rst: false,
            ack: true,
            psh: false,
            pure_ack: false,
            seq: 200,
            payload_len: 10,
        });
        assert_eq!(tcp.summary(), "S1 F0 R0 A0 X1");

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let key = FlowKey::new(ip1, ip2, 1234, 80, 6);
        let now = Instant::now();
        let mut stats = FlowStats::new(key, now);

        stats.record_endpoints(now, ip1, 1234, 500);
        assert_eq!(stats.bytes_a_to_b, 500);

        stats.record_endpoints(now, ip2, 80, 300);
        assert_eq!(stats.bytes_b_to_a, 300);

        stats.record(now, 800, Direction::Sent, None);
        assert_eq!(stats.total_bytes, 800);
        assert_eq!(stats.sent_bytes, 800);
        assert_eq!(stats.recv_bytes, 0);
        assert_eq!(stats.packets, 1);
    }

    #[test]
    fn test_flow_table_recording_and_sorting() {
        let mut table = FlowTable::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let local_addrs = vec![ip1];
        let now = Instant::now();

        table.set_show_ports(true);
        table.record(ip1, ip2, 1000, 80, 6, 1000, &local_addrs, now, None);
        table.record(ip2, ip1, 80, 1000, 6, 500, &local_addrs, now, None);

        assert_eq!(table.len(), 1);
        let g = table.globals();
        assert_eq!(g.packets_seen, 2);
        assert_eq!(g.packets_accepted, 2);
        assert_eq!(g.bytes_total, 1500);
        assert_eq!(g.bytes_sent, 1000);
        assert_eq!(g.bytes_recv, 500);

        // SortBy parsing
        assert_eq!(SortBy::parse("2s"), SortBy::Rate2s);
        assert_eq!(SortBy::parse("40S"), SortBy::Rate40s);
        assert_eq!(SortBy::parse("src"), SortBy::Source);
        assert_eq!(SortBy::parse("dst"), SortBy::Destination);
        assert_eq!(SortBy::parse("total"), SortBy::Total);
        assert_eq!(SortBy::parse("unknown"), SortBy::Rate10s);

        let top = table.top_sorted(10, now, SortBy::Total);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].total_bytes, 1500);

        // Expiration
        table.expire(now + Duration::from_secs(60), Duration::from_secs(30));
        assert_eq!(table.len(), 0);
    }
}
