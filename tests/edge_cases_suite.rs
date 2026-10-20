#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use riftop::alerts::{AlertConfig, AlertEngine};
use riftop::dns::DnsCache;
use riftop::export::{write_csv, write_json, write_text, OutputFormat};
use riftop::filters::{NetFilterV4, NetFilterV6};
use riftop::flow::{Aggregate, FlowKey, FlowTable, RateWindow, SortBy};
use riftop::top::{top_hosts, top_ports, top_protocols};

#[test]
fn test_flow_table_expire_regressed_timestamp() {
    let mut table = FlowTable::new();
    let start = Instant::now();
    let future = start + Duration::from_secs(10);
    let past = start;

    table.record(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        12345,
        80,
        6,
        1000,
        &[],
        future,
        None,
    );

    assert_eq!(table.len(), 1);

    // Call expire with a timestamp 'past' that is earlier than flow's 'last_seen' ('future').
    // Should handle gracefully without panicking due to Instant duration_since overflow.
    table.expire(past, Duration::from_secs(5));
    assert_eq!(
        table.len(),
        1,
        "Flow with future last_seen relative to now should not be expired or cause panic"
    );
}

#[test]
fn test_alert_engine_evaluate_regressed_timestamp() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(100.0),
        pps: Some(10.0),
    });

    let mut table = FlowTable::new();
    let t1 = Instant::now() + Duration::from_secs(10);
    let t0 = Instant::now();

    table.record(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        5000,
        80,
        6,
        500,
        &[],
        t1,
        None,
    );

    let snap1 = table.snapshot(10, t1);
    engine.evaluate(&snap1, t1);

    let snap0 = table.snapshot(10, t0);
    // Calling evaluate with t0 < t1 (timestamp regression) should not panic.
    engine.evaluate(&snap0, t0);
}

#[test]
fn test_dns_cache_control_characters_and_length_limit() {
    let cache = Arc::new(DnsCache::new());
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    // A hostname with control characters (newline, carriage return, escape code, null byte)
    let dirty_name = "malicious\nhost\r\x1b[31m.com\0extra";
    cache.insert(ip, Some(dirty_name.to_string()));

    if let Some(resolved) = cache.get(&ip) {
        assert!(
            !resolved.contains('\n')
                && !resolved.contains('\r')
                && !resolved.contains('\0')
                && !resolved.contains("\x1b["),
            "DnsCache should sanitize control characters from resolved hostnames, got: {:?}",
            resolved
        );
    }

    let long_ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    let long_name = "a".repeat(300) + ".example.com";
    cache.insert(long_ip, Some(long_name));

    if let Some(resolved) = cache.get(&long_ip) {
        assert!(
            resolved.len() <= 253,
            "DnsCache should bound hostname length to RFC 1035 limit (253 bytes), got length {}",
            resolved.len()
        );
    }
}

#[test]
fn test_rate_window_boundary_zero_age_and_overflow() {
    let mut rw = RateWindow::new(Duration::from_secs(0));
    let now = Instant::now();

    rw.add(now, 1000);
    let rate = rw.rate(now);
    assert!(
        rate.is_finite(),
        "Rate with zero max_age should return 0.0 or finite number without dividing by zero to NaN/Inf"
    );
    assert_eq!(rate, 0.0);

    // Large byte additions
    let mut rw_large = RateWindow::new(Duration::from_secs(10));
    rw_large.add(now, u64::MAX / 2);
    rw_large.add(now + Duration::from_millis(200), u64::MAX / 2);
    let rate_large = rw_large.rate(now + Duration::from_millis(200));
    assert!(
        rate_large.is_finite(),
        "Rate calculation for large byte sums should be finite"
    );
}

#[test]
fn test_net_filter_v4_and_v6_boundaries() {
    // Prefix 0
    let f0 = NetFilterV4::parse("0.0.0.0/0").expect("CIDR /0 should parse");
    assert!(f0.contains(Ipv4Addr::new(192, 168, 1, 1)));

    // Prefix 32
    let f32 = NetFilterV4::parse("192.168.1.1/32").expect("CIDR /32 should parse");
    assert!(f32.contains(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(!f32.contains(Ipv4Addr::new(192, 168, 1, 2)));

    // Prefix > 32 should error
    assert!(NetFilterV4::parse("10.0.0.0/33").is_err());

    // IPv6 Prefix 0
    let f6_0 = NetFilterV6::parse("::/0").expect("IPv6 CIDR /0 should parse");
    assert!(f6_0.contains(Ipv6Addr::LOCALHOST));

    // IPv6 Prefix 128
    let f6_128 = NetFilterV6::parse("2001:db8::1/128").expect("IPv6 CIDR /128 should parse");
    assert!(f6_128.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    assert!(!f6_128.contains(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)));

    // IPv6 Prefix > 128 should error
    assert!(NetFilterV6::parse("2001:db8::/129").is_err());

    // Malformed CIDR
    assert!(NetFilterV4::parse("invalid").is_err());
    assert!(NetFilterV6::parse("invalid").is_err());
}

#[test]
fn test_flow_key_aggregation_modes() {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Source aggregation without show_ports -> ports and protocol zeroed
    let k_source = FlowKey::aggregate(src, dst, 12345, 80, 6, Aggregate::Source, false);
    assert_eq!(k_source.a, src);
    assert_eq!(k_source.port_a, 0);
    assert_eq!(k_source.port_b, 0);
    assert_eq!(k_source.protocol, 0);

    // Source aggregation WITH show_ports -> sport and protocol preserved
    let k_source_ports = FlowKey::aggregate(src, dst, 12345, 80, 6, Aggregate::Source, true);
    assert_eq!(k_source_ports.a, src);
    assert_eq!(k_source_ports.port_a, 12345);
    assert_eq!(k_source_ports.port_b, 0);
    assert_eq!(k_source_ports.protocol, 6);

    // Destination aggregation
    let k_dst = FlowKey::aggregate(src, dst, 54321, 443, 6, Aggregate::Destination, true);
    assert_eq!(k_dst.b, dst);
    assert_eq!(k_dst.port_b, 443);
}

#[test]
fn test_export_formatting_extreme_values() {
    let mut table = FlowTable::new();
    let now = Instant::now();

    table.record(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        80,
        12345,
        6,
        1_000_000,
        &[],
        now,
        None,
    );

    // Test JSON export
    let mut json_buf = Vec::new();
    write_json(
        &mut json_buf,
        &table,
        now,
        10,
        "eth0\"weird_name\n",
        SortBy::Total,
    )
    .expect("JSON export should succeed");
    let json_str = String::from_utf8(json_buf).expect("JSON should be UTF-8");
    assert!(json_str.contains("eth0\\\"weird_name\\n"));
    assert!(json_str.contains("\"packets_seen\":1"));

    // Test Text export
    let mut text_buf = Vec::new();
    write_text(&mut text_buf, &table, now, 10, SortBy::Total, true)
        .expect("Text export should succeed");
    let text_str = String::from_utf8(text_buf).expect("Text should be UTF-8");
    assert!(text_str.contains("SRC\tDST"));

    // Test CSV export
    let mut csv_buf = Vec::new();
    write_csv(&mut csv_buf, &table, now, 10, SortBy::Total, false)
        .expect("CSV export should succeed");
    let csv_str = String::from_utf8(csv_buf).expect("CSV should be UTF-8");
    assert!(csv_str.contains("src,dst,sport,dport"));

    assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("text"), OutputFormat::Text);
}

#[test]
fn test_top_aggregation_empty_and_single() {
    let table = FlowTable::new();
    let now = Instant::now();
    let snap = table.snapshot(10, now);

    let hosts = top_hosts(&snap, now, 5);
    assert!(hosts.is_empty());

    let ports = top_ports(&snap, now, 5);
    assert!(ports.is_empty());

    let protos = top_protocols(&snap, now, 5);
    assert!(protos.is_empty());
}
