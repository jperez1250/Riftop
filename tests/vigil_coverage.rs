#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use riftop::alerts::{AlertConfig, AlertEngine};
use riftop::export::OutputFormat;
use riftop::flow::{format_bytes, format_duration, rate_bar, FlowTable, SortBy, TcpCounters};
use riftop::protocols::TcpFlags;
use riftop::top::{top_protocols, ViewMode};

#[test]
fn test_alert_engine_rate_and_pps_thresholds() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(500.0),
        pps: Some(10.0),
    });

    let mut table = FlowTable::new();
    let t0 = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Baseline record: 100 bytes, 1 packet
    table.record(a, b, 80, 80, 6, 100, &[a], t0, None);
    let snap0 = table.snapshot(10, t0);
    engine.evaluate(&snap0, t0);

    // Initial check should not trigger PPS alerts since there is no previous check
    assert_eq!(engine.latest_messages(10).len(), 0);

    // Advance 1 second, inject 50 packets and 10,000 bytes (pps = 50, rate_10s > 500)
    let t1 = t0 + Duration::from_secs(1);
    for _ in 0..50 {
        table.record(a, b, 80, 80, 6, 200, &[a], t1, None);
    }
    let snap1 = table.snapshot(10, t1);
    engine.evaluate(&snap1, t1);

    let messages = engine.latest_messages(10);
    assert!(
        messages.iter().any(|m| m.contains("PPS")),
        "Expected PPS alert when PPS exceeds threshold"
    );
    assert!(
        messages.iter().any(|m| m.contains("RATE")),
        "Expected RATE alert when flow rate exceeds threshold"
    );
}

#[test]
fn test_alert_engine_deduplication_and_max_keep() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(100.0),
        pps: None,
    });

    let t0 = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    let mut table = FlowTable::new();
    table.record(a, b, 443, 443, 6, 5000, &[a], t0, None);
    let snap = table.snapshot(10, t0);

    // Evaluate multiple times with identical snapshot -> should deduplicate
    engine.evaluate(&snap, t0);
    engine.evaluate(&snap, t0);
    engine.evaluate(&snap, t0);

    let msgs = engine.latest_messages(10);
    assert_eq!(
        msgs.len(),
        1,
        "Duplicate alert messages must be deduplicated"
    );

    // Test max_keep bounded buffer (20 max)
    let mut engine2 = AlertEngine::new(AlertConfig {
        rate_bps: Some(1.0),
        pps: None,
    });

    // Create 30 distinct flows to generate 30 distinct alerts
    let mut table2 = FlowTable::new();
    for i in 1..=30 {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 1, i));
        table2.record(src, dst, 80, 80, 6, 1000, &[src], t0, None);
    }
    let snap2 = table2.snapshot(50, t0);
    engine2.evaluate(&snap2, t0);

    assert_eq!(
        engine2.recent().count(),
        20,
        "Alert buffer must cap at max_keep (20)"
    );
}

#[test]
fn test_tcp_counters_flag_accounting_and_retransmissions() {
    let mut counters = TcpCounters::default();
    assert_eq!(counters.summary(), "");

    counters.observe(TcpFlags {
        syn: true,
        ack: false,
        fin: false,
        rst: false,
        psh: false,
        pure_ack: false,
        seq: 1000,
        payload_len: 0,
    });
    assert_eq!(counters.syn, 1);
    assert_eq!(counters.summary(), "S1 F0 R0 A0 X0");

    // Pure ACK
    counters.observe(TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: false,
        pure_ack: true,
        seq: 1001,
        payload_len: 0,
    });
    assert_eq!(counters.pure_ack, 1);

    // Data packet seq 2000
    counters.observe(TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: true,
        pure_ack: false,
        seq: 2000,
        payload_len: 500,
    });
    assert_eq!(counters.retrans, 0);

    // Retransmission of seq 2000
    counters.observe(TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: true,
        pure_ack: false,
        seq: 2000,
        payload_len: 500,
    });
    assert_eq!(counters.retrans, 1);

    // FIN and RST
    counters.observe(TcpFlags {
        syn: false,
        ack: false,
        fin: true,
        rst: true,
        psh: false,
        pure_ack: false,
        seq: 2500,
        payload_len: 0,
    });
    assert_eq!(counters.fin, 1);
    assert_eq!(counters.rst, 1);
    assert_eq!(counters.summary(), "S1 F1 R1 A1 X1");
}

#[test]
fn test_format_bytes_boundaries() {
    assert_eq!(format_bytes(0), "0.00 B");
    assert_eq!(format_bytes(9), "9.00 B");
    assert_eq!(format_bytes(50), "50.0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1023), "1023 B");
    assert_eq!(format_bytes(1024), "1.00 KB");
    assert_eq!(format_bytes(1024 * 50), "50.0 KB");
    assert_eq!(format_bytes(1024 * 100), "100 KB");
    assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    assert_eq!(format_bytes(1024 * 1024 * 1024 * 1024), "1.00 TB");
}

#[test]
fn test_format_duration_boundaries() {
    assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    assert_eq!(format_duration(Duration::from_secs(59)), "59s");
    assert_eq!(format_duration(Duration::from_secs(60)), "1m00s");
    assert_eq!(format_duration(Duration::from_secs(125)), "2m05s");
    assert_eq!(format_duration(Duration::from_secs(3599)), "59m59s");
    assert_eq!(format_duration(Duration::from_secs(3600)), "1h00m");
    assert_eq!(format_duration(Duration::from_secs(7325)), "2h02m");
}

#[test]
fn test_rate_bar_boundaries() {
    // Zero width
    assert_eq!(rate_bar(100.0, 100.0, 0), "");
    // Zero or negative max_rate
    assert_eq!(rate_bar(100.0, 0.0, 10), "          ");
    assert_eq!(rate_bar(100.0, -10.0, 10), "          ");
    // Zero rate
    assert_eq!(rate_bar(0.0, 100.0, 10), "          ");
    // Half rate
    assert_eq!(rate_bar(50.0, 100.0, 10), "#####     ");
    // Full rate
    assert_eq!(rate_bar(100.0, 100.0, 10), "##########");
    // Rate exceeding max
    assert_eq!(rate_bar(200.0, 100.0, 10), "##########");
}

#[test]
fn test_output_format_parsing() {
    assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("JSON"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("text"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("plain"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("CSV"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("other"), OutputFormat::Tui);
    assert_eq!(OutputFormat::parse(""), OutputFormat::Tui);
}

#[test]
fn test_sort_by_parsing() {
    assert_eq!(SortBy::parse("2s"), SortBy::Rate2s);
    assert_eq!(SortBy::parse("40s"), SortBy::Rate40s);
    assert_eq!(SortBy::parse("source"), SortBy::Source);
    assert_eq!(SortBy::parse("src"), SortBy::Source);
    assert_eq!(SortBy::parse("destination"), SortBy::Destination);
    assert_eq!(SortBy::parse("dst"), SortBy::Destination);
    assert_eq!(SortBy::parse("total"), SortBy::Total);
    assert_eq!(SortBy::parse("10s"), SortBy::Rate10s);
    assert_eq!(SortBy::parse("unknown"), SortBy::Rate10s);
}

#[test]
fn test_top_protocols_names() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.set_show_ports(true);
    // Protocol 1: ICMP
    table.record(a, b, 0, 0, 1, 100, &[a], now, None);
    // Protocol 6: TCP
    table.record(a, b, 80, 80, 6, 200, &[a], now, None);
    // Protocol 17: UDP
    table.record(a, b, 53, 53, 17, 300, &[a], now, None);
    // Protocol 58: ICMPv6
    table.record(a, b, 0, 0, 58, 400, &[a], now, None);
    // Protocol 0: any
    table.record(a, b, 0, 0, 0, 50, &[a], now, None);
    // Protocol 99: other
    table.record(a, b, 0, 0, 99, 60, &[a], now, None);

    let snap = table.snapshot(10, now);
    let proto_rows = top_protocols(&snap, now, 10);

    let labels: Vec<&str> = proto_rows.iter().map(|r| r.label.as_str()).collect();
    assert!(labels.contains(&"ICMP"));
    assert!(labels.contains(&"TCP"));
    assert!(labels.contains(&"UDP"));
    assert!(labels.contains(&"ICMPv6"));
    assert!(labels.contains(&"any"));
    assert!(labels.contains(&"other"));
}

#[test]
fn test_view_mode_titles_and_cycling() {
    assert_eq!(ViewMode::Flows.title(), "Top flows");
    assert_eq!(ViewMode::Hosts.title(), "Top hosts");
    assert_eq!(ViewMode::Ports.title(), "Top ports");
    assert_eq!(ViewMode::Protocols.title(), "Top protocols");

    assert_eq!(ViewMode::Flows.cycle(), ViewMode::Hosts);
    assert_eq!(ViewMode::Hosts.cycle(), ViewMode::Ports);
    assert_eq!(ViewMode::Ports.cycle(), ViewMode::Protocols);
    assert_eq!(ViewMode::Protocols.cycle(), ViewMode::Flows);
}
