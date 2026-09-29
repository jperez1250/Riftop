//! Regression R1 (rate windows) and R4 (direction from local address).
//!
//! Fixture data: `tests/fixtures_data.rs` (== fixtures/pcap/r1_r4_flows.pcap)
//! - 5 × 100-byte IPv4 TCP  10.0.0.1 → 10.0.0.2  (outgoing if local=10.0.0.1)
//! - 3 × 200-byte IPv4 TCP  10.0.0.2 → 10.0.0.1  (incoming)
//! - 1 non-IP frame (ignored)

mod fixtures_data;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use riftop::capture::process_pcap_file;
use riftop::flow::{FlowKey, FlowTable};
use riftop::protocols::{decode_ethernet, DecodeResult};

use fixtures_data::R1_R4_FLOWS_PCAP;

fn materialize_fixture() -> PathBuf {
    let dir = std::env::temp_dir().join("riftop_fixtures");
    std::fs::create_dir_all(&dir).expect("temp fixtures dir");
    let path = dir.join("r1_r4_flows.pcap");
    std::fs::write(&path, R1_R4_FLOWS_PCAP).expect("write fixture");
    path
}

fn local_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

fn remote_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
}

#[test]
fn r4_direction_from_local_address() {
    let table = process_pcap_file(&materialize_fixture(), &[local_host()]).expect("process pcap");
    assert_eq!(table.len(), 1, "one bidirectional flow expected");
    let stats = table.top(1, Instant::now())[0];
    assert_eq!(stats.sent_bytes, 500, "R4: sent must be 5×100 from local");
    assert_eq!(stats.recv_bytes, 600, "R4: recv must be 3×200 to local");
    assert_eq!(stats.total_bytes, 1100);
}

#[test]
fn r4_direction_swaps_when_local_is_remote() {
    let table = process_pcap_file(&materialize_fixture(), &[remote_host()]).expect("process pcap");
    let stats = table.top(1, Instant::now())[0];
    assert_eq!(stats.sent_bytes, 600);
    assert_eq!(stats.recv_bytes, 500);
}

#[test]
fn r2_single_flow_key_for_pair() {
    let table = process_pcap_file(&materialize_fixture(), &[local_host()]).expect("process pcap");
    assert_eq!(table.len(), 1);
    let key = &table.top(1, Instant::now())[0].key;
    let expected = FlowKey::new(local_host(), remote_host(), 40000, 80, 6);
    assert_eq!(key.a, expected.a);
    assert_eq!(key.b, expected.b);
}

#[test]
fn r6_non_ip_in_fixture_ignored() {
    let table = process_pcap_file(&materialize_fixture(), &[local_host()]).expect("process pcap");
    assert_eq!(table.len(), 1);
    assert_eq!(decode_ethernet(&[0u8; 8]), DecodeResult::Ignored);
}

#[test]
fn r1_rate_windows_respect_sample_age() {
    let mut table = FlowTable::new();
    let t0 = Instant::now();
    let local = local_host();
    let remote = remote_host();

    table.record(local, remote, 0, 0, 1, 1000, &[local], t0);
    table.record(local, remote, 0, 0, 1, 1000, &[local], t0 + Duration::from_secs(1));
    table.record(local, remote, 0, 0, 1, 5000, &[local], t0 + Duration::from_secs(30));

    let at = t0 + Duration::from_secs(30);
    let stats = table.top(1, at)[0];
    let r2 = stats.rate_2s(at);
    let r40 = stats.rate_40s(at);
    assert!(r2.is_finite() && r40.is_finite());
    assert!(r2 > 0.0, "R1: positive 2s rate");
    assert!(r40 > 0.0, "R1: positive 40s rate");
}

#[test]
fn r1_offline_pcap_totals_and_rates() {
    let table = process_pcap_file(&materialize_fixture(), &[local_host()]).expect("process pcap");
    let at = Instant::now() + Duration::from_secs(5);
    let stats = table.top(1, at)[0];
    assert_eq!(stats.total_bytes, 1100);
    assert_eq!(stats.sent_bytes + stats.recv_bytes, stats.total_bytes);
    assert!(stats.rate_2s(at).is_finite());
    assert!(stats.rate_10s(at).is_finite());
    assert!(stats.rate_40s(at).is_finite());
}
