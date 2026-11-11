#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::manual_repeat_n,
    clippy::float_cmp
)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use riftop::alerts::{AlertConfig, AlertEngine};
use riftop::export::{json_escape, write_csv, OutputFormat};
use riftop::flow::{FlowTable, SortBy, TcpCounters};
use riftop::protocols::TcpFlags;
use riftop::services::{format_endpoint, service_name};
use riftop::top::{format_top_row, top_ports, top_protocols, TopRow, ViewMode};

#[test]
fn test_alert_engine_rate_threshold_triggers_alert() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(500.0),
        pps: None,
    });

    let now = Instant::now();
    let mut table = FlowTable::new();
    let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    // Send 10,000 bytes within a 10s rate window
    table.record(src, dst, 0, 0, 6, 10_000, &[src], now, None);

    let snap = table.snapshot(10, now);
    engine.evaluate(&snap, now);

    let alerts = engine.latest_messages(5);
    assert_eq!(
        alerts.len(),
        1,
        "Expected one alert triggered for exceeding rate_bps threshold"
    );
    assert!(alerts[0].starts_with("RATE"));
    assert!(alerts[0].contains("192.168.1.10"));
    assert!(alerts[0].contains("192.168.1.20"));
}

#[test]
fn test_alert_engine_pps_threshold_evaluation() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: None,
        pps: Some(100.0),
    });

    let t0 = Instant::now();
    let mut table = FlowTable::new();
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Initial check establishes baseline packet count
    let snap0 = table.snapshot(10, t0);
    engine.evaluate(&snap0, t0);
    assert_eq!(engine.latest_messages(1).len(), 0);

    // 1 second later, 150 packets accepted (150 PPS > 100 PPS threshold)
    let t1 = t0 + Duration::from_secs(1);
    for _ in 0..150 {
        table.record(src, dst, 0, 0, 6, 64, &[src], t1, None);
    }
    let snap1 = table.snapshot(10, t1);
    engine.evaluate(&snap1, t1);

    let alerts = engine.latest_messages(1);
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].starts_with("PPS"));
    assert!(alerts[0].contains(">= 100"));
}

#[test]
fn test_alert_engine_deduplication_and_bounded_capacity() {
    let mut engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(10.0),
        pps: None,
    });

    let now = Instant::now();
    let mut table = FlowTable::new();
    let src = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2));

    table.record(src, dst, 0, 0, 6, 1_000, &[src], now, None);
    let snap = table.snapshot(10, now);

    // Evaluate twice with exact same message -> deduplication should keep only 1
    engine.evaluate(&snap, now);
    engine.evaluate(&snap, now);
    assert_eq!(engine.latest_messages(10).len(), 1);

    // Now trigger 25 distinct flow alerts to verify max_keep bounded limit of 20
    let mut multi_table = FlowTable::new();
    for i in 1..=25 {
        let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        multi_table.record(src, remote, 0, 0, 6, 10_000, &[src], now, None);
    }
    let snap_multi = multi_table.snapshot(30, now);
    let mut unbounded_engine = AlertEngine::new(AlertConfig {
        rate_bps: Some(10.0),
        pps: None,
    });
    unbounded_engine.evaluate(&snap_multi, now);

    let messages = unbounded_engine.latest_messages(50);
    assert_eq!(
        messages.len(),
        20,
        "Alert engine must cap recent history at max_keep (20)"
    );
}

#[test]
fn test_tcp_counters_observe_all_flags_and_retrans() {
    let mut counters = TcpCounters::default();
    assert_eq!(counters.summary(), "");

    // 1. SYN
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

    // 2. Pure ACK
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
    assert_eq!(counters.summary(), "S1 F0 R0 A1 X0");

    // 3. Data packet with payload
    counters.observe(TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: true,
        pure_ack: false,
        seq: 5000,
        payload_len: 1400,
    });
    assert_eq!(counters.retrans, 0);

    // 4. Retransmission with identical seq and payload > 0
    counters.observe(TcpFlags {
        syn: false,
        ack: true,
        fin: false,
        rst: false,
        psh: true,
        pure_ack: false,
        seq: 5000,
        payload_len: 1400,
    });
    assert_eq!(
        counters.retrans, 1,
        "Duplicate seq with payload should count as retransmission"
    );

    // 5. FIN and RST
    counters.observe(TcpFlags {
        syn: false,
        ack: true,
        fin: true,
        rst: true,
        psh: false,
        pure_ack: false,
        seq: 6400,
        payload_len: 0,
    });
    assert_eq!(counters.fin, 1);
    assert_eq!(counters.rst, 1);
    assert_eq!(counters.summary(), "S1 F1 R1 A1 X1");
}

#[test]
fn test_top_protocols_accounting_unknown_and_any() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Protocol 0 -> "any"
    table.record(a, b, 1000, 2000, 0, 100, &[a], now, None);
    // Protocol 99 -> "other"
    table.record(a, b, 1001, 2001, 99, 200, &[a], now, None);
    // Protocol 58 -> "ICMPv6"
    table.record(a, b, 1002, 2002, 58, 300, &[a], now, None);

    let snap = table.snapshot(10, now);
    let top = top_protocols(&snap, now, 10);

    assert_eq!(top.len(), 3);
    let icmp6 = top.iter().find(|p| p.label == "ICMPv6").unwrap();
    let other = top.iter().find(|p| p.label == "other").unwrap();
    let any = top.iter().find(|p| p.label == "any").unwrap();

    assert_eq!(icmp6.bytes, 300);
    assert_eq!(other.bytes, 200);
    assert_eq!(any.bytes, 100);
}

#[test]
fn test_top_ports_bidirectional_and_service_lookup() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Endpoint A: (10.0.0.1, 12345) <-> Endpoint B: (10.0.0.2, 443)
    // Key has a=10.0.0.1, port_a=12345, b=10.0.0.2, port_b=443
    // Send 1000 bytes from a:12345 to b:443
    table.record(a, b, 12345, 443, 6, 1000, &[a], now, None);
    // Send 2000 bytes back from b:443 to a:12345
    table.record(b, a, 443, 12345, 6, 2000, &[a], now, None);

    let snap = table.snapshot(10, now);
    assert_eq!(snap.flows.len(), 1);
    assert_eq!(snap.flows[0].bytes_a_to_b, 1000);
    assert_eq!(snap.flows[0].bytes_b_to_a, 2000);

    let ports = top_ports(&snap, now, 10);

    let p443 = ports.iter().find(|p| p.label.contains("443")).unwrap();
    assert_eq!(
        p443.bytes, 2000,
        "Port 443 is port_b, which tracks bytes_b_to_a (2000)"
    );
    assert!(
        p443.label.contains("(https)"),
        "Port 443 should resolve to service name https"
    );

    let p12345 = ports.iter().find(|p| p.label.contains("12345")).unwrap();
    assert_eq!(
        p12345.bytes, 1000,
        "Port 12345 is port_a, which tracks bytes_a_to_b (1000)"
    );
    assert_eq!(
        p12345.label, "12345",
        "Unknown port should remain unformatted without service parentheses"
    );
}

#[test]
fn test_top_viewmode_cycling_and_formatting() {
    let mut mode = ViewMode::Flows;
    assert_eq!(mode.title(), "Top flows");
    mode = mode.cycle();
    assert_eq!(mode, ViewMode::Hosts);
    assert_eq!(mode.title(), "Top hosts");
    mode = mode.cycle();
    assert_eq!(mode, ViewMode::Ports);
    assert_eq!(mode.title(), "Top ports");
    mode = mode.cycle();
    assert_eq!(mode, ViewMode::Protocols);
    assert_eq!(mode.title(), "Top protocols");
    mode = mode.cycle();
    assert_eq!(mode, ViewMode::Flows);

    let row = TopRow {
        label: "test-label".to_string(),
        bytes: 1048576,
        rate_2s: 5000.0,
        rate_10s: 2500.0,
        rate_40s: 1250.0,
    };
    let formatted = format_top_row(&row);
    assert_eq!(formatted.0, "test-label");
    assert!(!formatted.1.is_empty());
    assert!(!formatted.2.is_empty());
    assert!(!formatted.3.is_empty());
    assert!(formatted.4.contains("MB") || formatted.4.contains("M"));
}

#[test]
fn test_json_escape_special_characters_and_controls() {
    // Escaping quotation, backslash, control chars, tabs, newlines
    let input = "quote: \" backslash: \\ newline: \n cr: \r tab: \t control: \u{0007}";
    let escaped = json_escape(input);
    assert!(escaped.contains("\\\""));
    assert!(escaped.contains("\\\\"));
    assert!(escaped.contains("\\n"));
    assert!(escaped.contains("\\r"));
    assert!(escaped.contains("\\t"));
    assert!(escaped.contains("\\u0007"));
}

#[test]
fn test_output_format_parse_variations() {
    assert_eq!(OutputFormat::parse("json"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("JSON"), OutputFormat::Json);
    assert_eq!(OutputFormat::parse("text"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("plain"), OutputFormat::Text);
    assert_eq!(OutputFormat::parse("csv"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("CSV"), OutputFormat::Csv);
    assert_eq!(OutputFormat::parse("tui"), OutputFormat::Tui);
    assert_eq!(OutputFormat::parse("other"), OutputFormat::Tui);
}

#[test]
fn test_services_format_endpoint_combinations() {
    assert_eq!(format_endpoint("192.168.1.1", 0, 6, true), "192.168.1.1");
    assert_eq!(
        format_endpoint("192.168.1.1", 443, 6, true),
        "192.168.1.1:https"
    );
    assert_eq!(
        format_endpoint("192.168.1.1", 443, 6, false),
        "192.168.1.1:443"
    );
    assert_eq!(
        format_endpoint("192.168.1.1", 9999, 6, true),
        "192.168.1.1:9999"
    );
    assert_eq!(service_name(53, 17), Some("domain"));
    assert_eq!(service_name(80, 0), Some("http"));
}

#[test]
fn test_export_write_csv_bits_and_bytes_multipliers() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    table.record(a, b, 80, 80, 6, 2000, &[a], now, None);

    let mut buf_bytes = Vec::new();
    let mut buf_bits = Vec::new();

    write_csv(&mut buf_bytes, &table, now, 10, SortBy::Total, true).unwrap();
    write_csv(&mut buf_bits, &table, now, 10, SortBy::Total, false).unwrap();

    let csv_bytes = String::from_utf8(buf_bytes).unwrap();
    let csv_bits = String::from_utf8(buf_bits).unwrap();

    assert!(csv_bytes.contains("rate_2s_bytes_sec"));
    assert!(csv_bits.contains("rate_2s_bits_sec"));
}

#[test]
fn test_flow_table_sort_by_dest_and_source() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let b1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let b2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    table.record(a2, b1, 0, 0, 6, 100, &[a2], now, None);
    table.record(a1, b2, 0, 0, 6, 100, &[a1], now, None);

    let sorted_src = table.top_sorted(10, now, SortBy::Source);
    assert_eq!(sorted_src[0].key.a, a1);
    assert_eq!(sorted_src[1].key.a, a2);

    let sorted_dst = table.top_sorted(10, now, SortBy::Destination);
    assert_eq!(sorted_dst[0].key.b, b1);
    assert_eq!(sorted_dst[1].key.b, b2);
}
