#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]

//! Regression tests against PCAP fixtures (no root required).
//!
//! IDs: R1–R8 documented in docs/legacy-analysis.md

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Instant;

use riftop::export::json_escape;
use riftop::flow::{FlowKey, FlowTable};
use riftop::protocols::{decode_ethernet, DecodeResult};

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
fn expire_does_not_panic_when_now_is_before_last_seen() {
    let now = Instant::now();
    let future = now + std::time::Duration::from_secs(10);
    let past = now;
    let mut table = FlowTable::new();
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    table.record(a, b, 0, 0, 6, 100, &[a], future, None);
    assert_eq!(table.len(), 1);

    // Expire called with a timestamp `past` earlier than `future`
    table.expire(past, std::time::Duration::from_secs(5));
    assert_eq!(
        table.len(),
        1,
        "Flow with future timestamp must not cause panic when expiring"
    );
}

#[test]
fn alert_engine_does_not_panic_when_now_is_before_last_check() {
    use riftop::alerts::{AlertConfig, AlertEngine};
    let now = Instant::now();
    let future = now + std::time::Duration::from_secs(10);
    let past = now;

    let mut engine = AlertEngine::new(AlertConfig {
        pps: Some(10.0),
        rate_bps: None,
    });

    let table = FlowTable::new();
    let snap = table.snapshot(10, now);

    engine.evaluate(&snap, future);
    // Evaluate called with an earlier timestamp `past` relative to `future`
    engine.evaluate(&snap, past);
}

#[test]
fn negative_pcap_timestamp_does_not_panic() {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // Magic
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

    // Packet 1: Normal timestamp
    let frame = vec![0u8; 60];
    pcap.extend_from_slice(&100u32.to_le_bytes()); // ts_sec = 100
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&60u32.to_le_bytes());
    pcap.extend_from_slice(&60u32.to_le_bytes());
    pcap.extend_from_slice(&frame);

    // Packet 2: Corrupted header with extreme u32::MAX ts_sec (e.g. -1 as i32 or 4 billion seconds)
    pcap.extend_from_slice(&0xffffffffu32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&60u32.to_le_bytes());
    pcap.extend_from_slice(&60u32.to_le_bytes());
    pcap.extend_from_slice(&frame);

    let temp_file = std::env::temp_dir().join("riftop_neg_ts.pcap");
    std::fs::write(&temp_file, &pcap).unwrap();

    let _ = riftop::capture::process_pcap_file(&temp_file, &[]);
    let _ = std::fs::remove_file(&temp_file);
}
