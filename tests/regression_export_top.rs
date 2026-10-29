#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use riftop::export::{write_csv, write_json, write_text};
use riftop::flow::{FlowTable, SortBy};
use riftop::top::{top_hosts, top_ports, top_protocols, ViewMode};

#[test]
fn test_export_empty_table() {
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
    assert!(text_str.contains("# packets_seen=0"));

    let mut csv_buf = Vec::new();
    write_csv(&mut csv_buf, &table, now, 10, SortBy::Rate10s, false).unwrap();
    let csv_str = String::from_utf8(csv_buf).unwrap();
    assert!(csv_str.starts_with("src,dst,sport,dport,proto,sent,recv,total"));
}

#[test]
fn test_export_json_escaping_interface() {
    let table = FlowTable::new();
    let now = Instant::now();

    let mut json_buf = Vec::new();
    write_json(
        &mut json_buf,
        &table,
        now,
        10,
        "eth0\n\"test\"",
        SortBy::Rate10s,
    )
    .unwrap();
    let json_str = String::from_utf8(json_buf).unwrap();
    assert!(json_str.contains("\"interface\":\"eth0\\n\\\"test\\\"\""));
}

#[test]
fn test_export_with_flows_and_sort_modes() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();

    let local = IpAddr::from_str("10.0.0.1").unwrap();
    let remote1 = IpAddr::from_str("10.0.0.2").unwrap();
    let remote2 = IpAddr::from_str("10.0.0.3").unwrap();

    table.record(local, remote1, 12345, 80, 6, 1000, &[local], now, None);
    table.record(local, remote2, 54321, 443, 6, 5000, &[local], now, None);

    for sort_mode in [
        SortBy::Rate2s,
        SortBy::Rate10s,
        SortBy::Rate40s,
        SortBy::Total,
        SortBy::Source,
        SortBy::Destination,
    ] {
        let mut json_buf = Vec::new();
        write_json(&mut json_buf, &table, now, 10, "eth0", sort_mode).unwrap();
        let json_str = String::from_utf8(json_buf).unwrap();
        assert!(json_str.contains("\"flow_count\":2"));

        let mut text_buf = Vec::new();
        write_text(&mut text_buf, &table, now, 10, sort_mode, true).unwrap();
        let text_str = String::from_utf8(text_buf).unwrap();
        assert!(text_str.contains("10.0.0.1"));

        let mut csv_buf = Vec::new();
        write_csv(&mut csv_buf, &table, now, 10, sort_mode, false).unwrap();
        let csv_str = String::from_utf8(csv_buf).unwrap();
        assert!(csv_str.contains("10.0.0.2"));
    }
}

#[test]
fn test_top_aggregations_and_view_mode() {
    let mut table = FlowTable::new();
    table.set_show_ports(true);
    let now = Instant::now();

    let ip_a = IpAddr::from_str("10.0.0.1").unwrap();
    let ip_b = IpAddr::from_str("10.0.0.2").unwrap();

    // Flow 1: TCP port 80 -> HTTP
    table.record(ip_a, ip_b, 10000, 80, 6, 2000, &[ip_a], now, None);
    // Flow 2: UDP port 53 -> DNS
    table.record(ip_a, ip_b, 20000, 53, 17, 500, &[ip_a], now, None);
    // Flow 3: ICMP (proto 1, ports 0)
    table.record(ip_a, ip_b, 0, 0, 1, 100, &[ip_a], now, None);

    let snap = table.snapshot(10, now);

    let hosts = top_hosts(&snap, now, 5);
    assert!(!hosts.is_empty());

    let ports = top_ports(&snap, now, 5);
    assert!(ports
        .iter()
        .any(|p| p.label.contains("80") || p.label.contains("http")));

    let protos = top_protocols(&snap, now, 5);
    assert!(protos
        .iter()
        .any(|pr| pr.label.to_lowercase().contains("tcp")));
    assert!(protos
        .iter()
        .any(|pr| pr.label.to_lowercase().contains("udp")));
    assert!(protos
        .iter()
        .any(|pr| pr.label.to_lowercase().contains("icmp")));

    let mode = ViewMode::Flows;
    assert_eq!(mode.title(), "Top flows");
    assert_eq!(mode.cycle(), ViewMode::Hosts);
    assert_eq!(mode.cycle().cycle(), ViewMode::Ports);
}
