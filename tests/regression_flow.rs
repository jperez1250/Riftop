//! Regression tests against PCAP fixtures (no root required).
//!
//! IDs: R1–R8 documented in docs/legacy-analysis.md

#![allow(clippy::unwrap_used, clippy::expect_used)]

use riftop::export::json_escape;
use riftop::flow::{FlowKey, FlowTable, RateWindow};
use riftop::protocols::{decode_ethernet, DecodeResult};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn json_escaping_special_chars() {
    assert_eq!(json_escape("eth0"), "eth0");
    assert_eq!(json_escape("eth\"0"), "eth\\\"0");
    assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
}

#[test]
fn r2_flow_key_is_bidirectional() {
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let k1 = FlowKey::new(a, b, 80, 443, 6);
    let k2 = FlowKey::new(b, a, 443, 80, 6);
    assert_eq!(k1, k2, "R2: A↔B must be a single flow key");
}

#[test]
fn r6_unsupported_frames_do_not_panic() {
    assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
    assert_eq!(decode_ethernet(&[0u8; 4]), DecodeResult::Ignored);
}

#[test]
fn r1_rate_windows_exist() {
    let now = Instant::now();
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        0,
        0,
        1,
    );
    let mut table = FlowTable::new();
    table.record(
        key.a,
        key.b,
        key.port_a,
        key.port_b,
        key.protocol,
        1500,
        &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        now,
        None,
    );
    let top = table.top(1, now);
    assert_eq!(top.len(), 1);
    let r2 = top[0].rate_2s(now);
    let r10 = top[0].rate_10s(now);
    let r40 = top[0].rate_40s(now);
    assert!(r2.is_finite() && r10.is_finite() && r40.is_finite());
}

#[test]
fn fixture_directory_exists() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/pcap");
    assert!(
        dir.is_dir(),
        "fixtures/pcap must exist for regression fixtures"
    );
}

#[test]
fn test_expire_handles_timestamp_regression() {
    let mut table = FlowTable::new();
    let now = Instant::now();
    let future = now + Duration::from_secs(5);
    table.record(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        1234,
        80,
        6,
        100,
        &[],
        future,
        None,
    );
    // expire called with `now` (< last_seen `future`) must not panic
    table.expire(now, Duration::from_secs(30));
    assert_eq!(table.len(), 1);
}

#[test]
fn test_rate_window_out_of_order_sample_not_merged() {
    let mut window = RateWindow::new(Duration::from_secs(10));
    let t_10s = Instant::now() + Duration::from_secs(20);
    let t_12s_old = t_10s - Duration::from_secs(12);

    window.add(t_10s, 100);
    window.add(t_12s_old, 50);

    // Out-of-order sample 12s older than t_10s must not merge into t_10s sample bucket,
    // and must be excluded from rate calculation at t_10s since it is beyond max_age (10s).
    let rate = window.rate(t_10s);
    assert!((rate - 10.0).abs() < 1e-5);
}
