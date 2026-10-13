//! Integration stress and edge-case test suite for Riftop.
//! Covers malformed packets, DNS cache limits, rate window boundary conditions,
//! export formatting edge cases, and flow aggregation under stress.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::manual_repeat_n
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use riftop::dns::DnsCache;
use riftop::export::{write_csv, write_json, write_text};
use riftop::flow::{format_rate, format_rate_units, Aggregate, FlowKey, FlowTable, RateWindow, SortBy};
use riftop::protocols::{decode_ethernet, decode_frame, DecodeResult};
use riftop::top::{top_hosts, top_ports, top_protocols};

// ============================================================================
// 1. MALFORMED / TRUNCATED PACKET DECODING STRESS
// ============================================================================

#[test]
fn test_decode_empty_and_truncated_frames() {
    assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
    assert_eq!(decode_frame(1, &[]), DecodeResult::Ignored);

    // Truncated Ethernet header (<14 bytes)
    let short_eth = vec![0x00, 0x01, 0x02, 0x03];
    assert_eq!(decode_ethernet(&short_eth), DecodeResult::Ignored);

    // Short IPv4 header (<20 bytes)
    let mut short_ip = Vec::from(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00][..]);
    short_ip.extend_from_slice(&[0x45, 0x00, 0x00, 0x20]); // IHL=5 but payload truncated
    assert_eq!(decode_ethernet(&short_ip), DecodeResult::Ignored);

    // Short IPv6 header (<40 bytes)
    let mut short_ipv6 = Vec::from(&[0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x86, 0xDD][..]);
    short_ipv6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    assert_eq!(decode_ethernet(&short_ipv6), DecodeResult::Ignored);
}

#[test]
fn test_decode_fuzzed_garbage_frames_no_panic() {
    let mut seed: u32 = 0xdeadbeef;
    for len in [1, 5, 13, 14, 15, 20, 34, 40, 54, 100] {
        for _ in 0..100 {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                buf.push((seed >> 16) as u8);
            }
            // Must not panic on garbage bytes for any DLT
            let _ = decode_ethernet(&buf);
            let _ = decode_frame(1, &buf);
            let _ = decode_frame(12, &buf);
            let _ = decode_frame(113, &buf);
            let _ = decode_frame(276, &buf);
        }
    }
}

// ============================================================================
// 2. DNS CACHE BOUNDARY STRESS
// ============================================================================

#[test]
fn test_dns_cache_insert_and_retrieval() {
    let cache = Arc::new(DnsCache::new());
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    let host_name = "example.com".to_string();
    cache.insert(ip, Some(host_name.clone()));

    let resolved = cache.get(&ip).expect("host resolved");
    assert_eq!(resolved, host_name);
}

#[test]
fn test_dns_cache_display_fallbacks() {
    let cache = Arc::new(DnsCache::new());
    let ip_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

    // Unresolved when no_dns is true should format IP directly
    assert_eq!(cache.display(&ip_v4, false), "10.0.0.1");
    assert_eq!(cache.display(&ip_v6, false), "::1");

    // Unresolved when no_dns is false (cache miss before async resolve finishes)
    assert_eq!(cache.display(&ip_v4, true), "10.0.0.1");

    // Failed lookup stored as None
    cache.insert(ip_v4, None);
    assert_eq!(cache.display(&ip_v4, true), "10.0.0.1");
}

// ============================================================================
// 3. RATE WINDOW & NUMERICAL BOUNDARY STRESS
// ============================================================================

#[test]
fn test_rate_window_out_of_order_and_durations() {
    let mut rw = RateWindow::new(Duration::from_secs(10));
    let t0 = Instant::now();

    // Adding samples in non-chronological order
    rw.add(t0 + Duration::from_secs(5), 500);
    rw.add(t0 + Duration::from_secs(1), 100); // Older sample
    rw.add(t0 + Duration::from_secs(10), 1000);

    let rate = rw.rate(t0 + Duration::from_secs(10));
    assert!(rate >= 0.0);
    assert!(rate.is_finite());
}

#[test]
fn test_format_rate_units_extremes() {
    assert_eq!(format_rate(0.0), "0.00 b");
    assert!(!format_rate(f64::MAX).is_empty());
    assert!(!format_rate(f64::MIN_POSITIVE).is_empty());

    let b_sec = format_rate_units(1024.0, true);
    let b_bit = format_rate_units(1024.0, false);
    assert!(b_sec.contains("B"));
    assert!(b_bit.contains("b"));
}

// ============================================================================
// 4. FLOW AGGREGATION, TOP STATS, AND EXPORT FORMATTING STRESS
// ============================================================================

#[test]
fn test_flow_table_aggregate_modes() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.set_aggregate(Aggregate::Source);
    table.record(src, dst, 1234, 80, 6, 100, &[src], now, None);

    let snap = table.snapshot(10, now);
    assert_eq!(snap.flows.len(), 1);
    assert_eq!(snap.flows[0].key.a, src);
    assert_eq!(snap.flows[0].key.b, IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    let mut table_dst = FlowTable::new();
    table_dst.set_aggregate(Aggregate::Destination);
    table_dst.record(src, dst, 1234, 80, 6, 100, &[src], now, None);

    let snap_dst = table_dst.snapshot(10, now);
    assert_eq!(snap_dst.flows[0].key.a, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(snap_dst.flows[0].key.b, dst);
}

#[test]
fn test_top_statistics_empty_snapshot() {
    let table = FlowTable::new();
    let now = Instant::now();
    let snap = table.snapshot(10, now);

    assert!(top_hosts(&snap, now, 10).is_empty());
    assert!(top_ports(&snap, now, 10).is_empty());
    assert!(top_protocols(&snap, now, 10).is_empty());
}

#[test]
fn test_export_formatting_special_characters_and_escaping() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(src, dst, 80, 80, 6, 100, &[src], now, None);

    let mut json_buf = Vec::new();
    let mut csv_buf = Vec::new();
    let mut text_buf = Vec::new();

    write_json(&mut json_buf, &table, now, 10, "iface\"with'quotes", SortBy::Rate10s).unwrap();
    write_csv(&mut csv_buf, &table, now, 10, SortBy::Rate10s, false).unwrap();
    write_text(&mut text_buf, &table, now, 10, SortBy::Rate10s, false).unwrap();

    let json_str = String::from_utf8(json_buf).unwrap();
    let csv_str = String::from_utf8(csv_buf).unwrap();
    let text_str = String::from_utf8(text_buf).unwrap();

    assert!(json_str.contains("iface\\\"with'quotes"));
    assert!(!csv_str.is_empty());
    assert!(!text_str.is_empty());
}

#[test]
fn test_flow_key_ordering_canonicalization() {
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let key1 = FlowKey::new(ip1, ip2, 1000, 80, 6);
    let key2 = FlowKey::new(ip2, ip1, 80, 1000, 6);

    assert_eq!(key1, key2);
    assert!(key1.a <= key1.b);
}
