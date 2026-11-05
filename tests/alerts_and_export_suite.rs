//! Integration tests for AlertEngine, Export formats, and FlowTable lifecycle edge cases.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]

use std::net::IpAddr;
use std::time::{Duration, Instant};

use riftop::alerts::{AlertConfig, AlertEngine};
use riftop::export::{json_escape, write_csv, write_json, write_text, OutputFormat};
use riftop::flow::{FlowTable, SortBy};

#[test]
fn test_output_format_parse() {
    assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("JSON"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("text"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("TEXT"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("plain"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("CSV"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("tui"), OutputFormat::Tui);
    assert_eq!(OutputFormat::parse("unknown_format"), OutputFormat::Tui);
    assert_eq!(OutputFormat::parse(""), OutputFormat::Tui);
}

#[test]
fn test_json_escape_comprehensive() {
    assert_eq!(json_escape("simple text"), "simple text");
    assert_eq!(json_escape("quotes: \"hello\""), "quotes: \\\"hello\\\"");
    assert_eq!(json_escape("backslash: \\path"), "backslash: \\\\path");
    assert_eq!(
        json_escape("newline\nand\rreturn\tand tab"),
        "newline\\nand\\rreturn\\tand tab"
    );
    assert_eq!(json_escape("\u{0000}\u{001f}"), "\\u0000\\u001f");
    assert_eq!(json_escape("Unicode: 🚀 é ñ 測試"), "Unicode: 🚀 é ñ 測試");
}

#[test]
fn test_alert_engine_empty_config() {
    let mut engine = AlertEngine::new(AlertConfig::default());
    let table = FlowTable::new();
    let now = Instant::now();
    let snap = table.snapshot(10, now);

    engine.evaluate(&snap, now);
    assert_eq!(engine.recent().count(), 0);
    assert!(engine.latest_messages(5).is_empty());
}

#[test]
fn test_alert_engine_rate_threshold_triggering() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(100.0), // 100 bytes/sec threshold
        pps: None,
    });

    let mut table = FlowTable::new();
    let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.1".parse().unwrap();
    let start = Instant::now();

    // Record high traffic over time
    table.record(ip_a, ip_b, 80, 443, 6, 2_000, &[], start, None);
    let later = start + Duration::from_secs(5);
    table.record(ip_a, ip_b, 80, 443, 6, 2_000, &[], later, None);

    let snap = table.snapshot(10, later);
    engine.evaluate(&snap, later);

    let msgs = engine.latest_messages(10);
    assert_eq!(msgs.len(), 1, "Expected 1 rate alert");
    // Endpoints in FlowKey are canonicalized: 10.0.0.1 <= 192.168.1.1
    assert!(msgs[0].contains("RATE 10.0.0.1 \u{2194} 192.168.1.1"));
    assert!(msgs[0].contains(">="));

    // Evaluate again with identical state -> deduplication should prevent adding duplicate
    engine.evaluate(&snap, later);
    assert_eq!(engine.latest_messages(10).len(), 1, "Deduplication failed");
}

#[test]
fn test_alert_engine_rate_below_threshold() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(10_000_000.0), // very high threshold
        pps: None,
    });

    let mut table = FlowTable::new();
    let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.1".parse().unwrap();
    let start = Instant::now();

    table.record(ip_a, ip_b, 80, 443, 6, 100, &[], start, None);
    let snap = table.snapshot(10, start);
    engine.evaluate(&snap, start);

    assert_eq!(engine.recent().count(), 0);
}

#[test]
fn test_alert_engine_pps_calculation_and_triggering() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: None,
        pps: Some(50.0), // 50 pkts/sec threshold
    });

    let mut table = FlowTable::new();
    let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.1".parse().unwrap();
    let t0 = Instant::now();

    // First check initializes last_pkt_count & last_check
    table.record(ip_a, ip_b, 80, 443, 6, 100, &[], t0, None);
    let snap0 = table.snapshot(10, t0);
    engine.evaluate(&snap0, t0);
    assert_eq!(engine.recent().count(), 0);

    // After 1 second, add 100 packets
    let t1 = t0 + Duration::from_secs(1);
    for _ in 0..100 {
        table.record(ip_a, ip_b, 80, 443, 6, 50, &[], t1, None);
    }
    let snap1 = table.snapshot(10, t1);
    engine.evaluate(&snap1, t1);

    let msgs = engine.latest_messages(5);
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].starts_with("PPS "));
    assert!(msgs[0].contains(">= 50"));
}

#[test]
fn test_alert_engine_pps_below_threshold() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: None,
        pps: Some(100.0),
    });

    let mut table = FlowTable::new();
    let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.1".parse().unwrap();
    let t0 = Instant::now();

    table.record(ip_a, ip_b, 80, 443, 6, 100, &[], t0, None);
    let snap0 = table.snapshot(10, t0);
    engine.evaluate(&snap0, t0);

    let t1 = t0 + Duration::from_secs(1);
    // Only 10 packets in 1 sec => 10 PPS < 100 PPS
    for _ in 0..10 {
        table.record(ip_a, ip_b, 80, 443, 6, 50, &[], t1, None);
    }
    let snap1 = table.snapshot(10, t1);
    engine.evaluate(&snap1, t1);

    assert_eq!(engine.recent().count(), 0);
}

#[test]
fn test_alert_engine_capacity_bounded_to_20() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(1.0),
        pps: None,
    });

    let start = Instant::now();
    // Create 30 distinct flows that each trigger a distinct rate alert
    for i in 1..=30 {
        let mut table = FlowTable::new();
        let ip_a: IpAddr = format!("192.168.1.{i}").parse().unwrap();
        let ip_b: IpAddr = format!("10.0.0.{i}").parse().unwrap();
        table.record(ip_a, ip_b, 80, 443, 6, 50_000, &[], start, None);
        let snap = table.snapshot(10, start);
        engine.evaluate(&snap, start);
    }

    assert_eq!(
        engine.recent().count(),
        20,
        "Alert history must be bounded at max_keep=20"
    );
    assert_eq!(engine.latest_messages(50).len(), 20);

    // Most recent alert (index 0) should be from i=30
    let latest = engine.latest_messages(1);
    assert_eq!(latest.len(), 1);
    assert!(latest[0].contains("192.168.1.30"));
}

#[test]
fn test_alert_engine_latest_messages_boundaries() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(1.0),
        pps: None,
    });

    let now = Instant::now();
    let mut table = FlowTable::new();
    let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.1".parse().unwrap();
    table.record(ip_a, ip_b, 80, 443, 6, 10_000, &[], now, None);
    let snap = table.snapshot(10, now);
    engine.evaluate(&snap, now);

    assert_eq!(engine.latest_messages(0).len(), 0);
    assert_eq!(engine.latest_messages(1).len(), 1);
    assert_eq!(engine.latest_messages(10).len(), 1);
}

#[test]
fn test_export_empty_flow_table() {
    let table = FlowTable::new();
    let now = Instant::now();

    let mut json_buf = Vec::new();
    write_json(&mut json_buf, &table, now, 10, "eth0", SortBy::Rate10s).unwrap();
    let json_str = String::from_utf8(json_buf).unwrap();
    assert!(json_str.contains("\"interface\":\"eth0\""));
    assert!(json_str.contains("\"flow_count\":0"));
    assert!(json_str.contains("\"flows\":[]"));

    let mut text_buf = Vec::new();
    write_text(&mut text_buf, &table, now, 10, SortBy::Rate10s, true).unwrap();
    let text_str = String::from_utf8(text_buf).unwrap();
    assert!(text_str.contains("# packets_seen=0 accepted=0 bytes=0.00 B flows=0"));
    assert!(text_str.contains("# SRC\tDST\t2s\t10s\t40s\tTOTAL"));

    let mut csv_buf = Vec::new();
    write_csv(&mut csv_buf, &table, now, 10, SortBy::Rate10s, false).unwrap();
    let csv_str = String::from_utf8(csv_buf).unwrap();
    assert!(csv_str.starts_with("src,dst,sport,dport,proto,sent,recv,total,rate_2s_bits_sec,rate_10s_bits_sec,rate_40s_bits_sec"));
    // Exactly 1 line of headers
    assert_eq!(csv_str.trim().lines().count(), 1);
}

#[test]
fn test_export_populated_flow_table_formats() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();
    let ip_a: IpAddr = "1.2.3.4".parse().unwrap();
    let ip_b: IpAddr = "5.6.7.8".parse().unwrap();
    let local = [ip_a];

    table.record(ip_a, ip_b, 1234, 80, 6, 1_500, &local, now, None);

    // JSON export test
    let mut json_buf = Vec::new();
    write_json(&mut json_buf, &table, now, 5, "wlan0", SortBy::Total).unwrap();
    let json_str = String::from_utf8(json_buf).unwrap();
    assert!(json_str.contains("\"interface\":\"wlan0\""));
    assert!(json_str.contains("\"packets_seen\":1"));
    assert!(json_str.contains("\"packets_accepted\":1"));
    assert!(json_str.contains("\"bytes_total\":1500"));
    assert!(json_str.contains("\"bytes_sent\":1500"));
    assert!(json_str.contains("\"bytes_recv\":0"));
    assert!(json_str.contains("\"flow_count\":1"));
    assert!(json_str.contains("\"sport\":1234"));
    assert!(json_str.contains("\"dport\":80"));
    assert!(json_str.contains("\"proto\":6"));

    // Text export with bytes
    let mut text_buf = Vec::new();
    write_text(&mut text_buf, &table, now, 5, SortBy::Source, true).unwrap();
    let text_str = String::from_utf8(text_buf).unwrap();
    let lines: Vec<&str> = text_str.trim().lines().collect();
    assert_eq!(lines.len(), 3); // 2 header lines + 1 flow line
    assert!(lines[2].contains("1.2.3.4"));
    assert!(lines[2].contains("5.6.7.8"));

    // Text export with bits
    let mut text_buf_bits = Vec::new();
    write_text(&mut text_buf_bits, &table, now, 5, SortBy::Source, false).unwrap();
    let text_str_bits = String::from_utf8(text_buf_bits).unwrap();
    assert!(text_str_bits.contains("1.2.3.4"));

    // CSV export with bytes
    let mut csv_buf_bytes = Vec::new();
    write_csv(
        &mut csv_buf_bytes,
        &table,
        now,
        5,
        SortBy::Destination,
        true,
    )
    .unwrap();
    let csv_str_bytes = String::from_utf8(csv_buf_bytes).unwrap();
    let csv_lines: Vec<&str> = csv_str_bytes.trim().lines().collect();
    assert_eq!(csv_lines.len(), 2);
    assert!(csv_lines[0].contains("rate_2s_bytes_sec"));
    let cols: Vec<&str> = csv_lines[1].split(',').collect();
    assert_eq!(cols.len(), 11, "CSV row must have exactly 11 columns");
    assert_eq!(cols[0], "1.2.3.4");
    assert_eq!(cols[1], "5.6.7.8");
    assert_eq!(cols[2], "1234");
    assert_eq!(cols[3], "80");
    assert_eq!(cols[4], "6");
    assert_eq!(cols[5], "1500"); // sent
    assert_eq!(cols[6], "0"); // recv
    assert_eq!(cols[7], "1500"); // total

    // CSV export with bits
    let mut csv_buf_bits = Vec::new();
    write_csv(&mut csv_buf_bits, &table, now, 5, SortBy::Rate40s, false).unwrap();
    let csv_str_bits = String::from_utf8(csv_buf_bits).unwrap();
    assert!(csv_str_bits.contains("rate_2s_bits_sec"));
}

#[test]
fn test_flow_table_expiration_and_limits() {
    let mut table = FlowTable::new();
    let start = Instant::now();
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    table.record(ip1, ip2, 100, 200, 6, 500, &[], start, None);
    assert_eq!(table.len(), 1);

    // Expire with generous idle window => retained
    table.expire(start + Duration::from_secs(10), Duration::from_secs(30));
    assert_eq!(table.len(), 1);

    // Expire with expired idle window => pruned
    table.expire(start + Duration::from_secs(40), Duration::from_secs(30));
    assert_eq!(table.len(), 0);
    assert!(table.is_empty());
}
