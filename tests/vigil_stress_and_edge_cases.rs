#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]

use std::net::IpAddr;
use std::time::{Duration, Instant};

use riftop::alerts::{AlertConfig, AlertEngine};
use riftop::dns::DnsCache;
use riftop::export::{json_escape, write_csv, write_json, write_text, OutputFormat};
use riftop::filters::PacketFilter;
use riftop::flow::{Aggregate, FlowTable, SortBy};

#[test]
fn test_export_formatting_and_json_escaping() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let src: IpAddr = "10.0.0.1".parse().unwrap();
    let dst: IpAddr = "10.0.0.2".parse().unwrap();

    table.record(src, dst, 1234, 80, 6, 1024, &[], now, None);

    let dns = DnsCache::new();
    dns.insert(src, Some("host\"with\\quotes\nand_newlines".to_string()));

    let mut json_buf = Vec::new();
    write_json(&mut json_buf, &table, now, 10, "eth0\"test", SortBy::Total).unwrap();
    let json_str = String::from_utf8(json_buf).unwrap();

    assert!(json_str.contains("eth0\\\"test"));
    assert!(json_str.contains("\"bytes_total\":1024"));

    let mut text_buf = Vec::new();
    write_text(&mut text_buf, &table, now, 10, SortBy::Total, true).unwrap();
    let text_str = String::from_utf8(text_buf).unwrap();

    assert!(text_str.contains("1.00 KB"));

    let mut csv_buf = Vec::new();
    write_csv(&mut csv_buf, &table, now, 10, SortBy::Total, false).unwrap();
    let csv_str = String::from_utf8(csv_buf).unwrap();

    assert!(csv_str.contains("bits_sec"));

    assert_eq!(json_escape("hello\tworld\n\""), "hello\\tworld\\n\\\"");
    assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("plain"), OutputFormat::Text);
}

#[test]
fn test_flow_table_stress() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let dst: IpAddr = "192.168.1.1".parse().unwrap();

    for i in 0..1_000 {
        let b2 = (i >> 8) as u8;
        let b3 = i as u8;
        let src = IpAddr::from([10, 0, b2, b3]);
        table.record(src, dst, 1000 + (i % 100) as u16, 80, 6, 64, &[], now, None);
    }

    assert_eq!(table.len(), 1000);
    assert_eq!(table.globals().packets_seen, 1000);
}

#[test]
fn test_packet_filter_and_flow_table_integration() {
    let filter = PacketFilter::from_options(Some("192.168.0.0/16"), None, false).unwrap();

    let mut table = FlowTable::new();
    table.set_aggregate(Aggregate::Pair);

    let inside: IpAddr = "192.168.1.10".parse().unwrap();
    let outside: IpAddr = "8.8.8.8".parse().unwrap();
    let now = Instant::now();

    // Accepted crossing boundary flow
    let accepted = table.record_filtered(
        inside,
        outside,
        50000,
        443,
        6,
        1500,
        &[],
        now,
        &filter,
        None,
    );
    assert!(accepted);
    assert_eq!(table.globals().packets_accepted, 1);

    // Rejected non-crossing or non-matching flow
    let rejected = table.record_filtered(outside, outside, 80, 80, 6, 100, &[], now, &filter, None);
    assert!(!rejected);
    assert_eq!(table.globals().packets_seen, 2);
    assert_eq!(table.globals().packets_accepted, 1);
}

#[test]
fn test_alert_engine_stress_and_time_jump() {
    let mut alerts = AlertEngine::new(AlertConfig {
        rate_bps: Some(500.0),
        pps: Some(50.0),
    });

    let mut table = FlowTable::new();
    let t0 = Instant::now();
    let src: IpAddr = "10.0.0.1".parse().unwrap();
    let dst: IpAddr = "10.0.0.2".parse().unwrap();

    table.record(src, dst, 1000, 80, 6, 10_000, &[], t0, None);

    let snap0 = table.snapshot_sorted(10, t0, SortBy::Rate10s);
    alerts.evaluate(&snap0, t0);

    // Forward time jump by 1 hour
    let t1 = t0 + Duration::from_secs(3600);
    let snap1 = table.snapshot_sorted(10, t1, SortBy::Rate10s);
    alerts.evaluate(&snap1, t1);

    // Backward time jump (regression) by 30 minutes
    let t_past = t1 - Duration::from_secs(1800);
    let snap_past = table.snapshot_sorted(10, t_past, SortBy::Rate10s);
    alerts.evaluate(&snap_past, t_past);
}
