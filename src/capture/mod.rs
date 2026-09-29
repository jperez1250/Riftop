//! Packet capture: live device and offline PCAP.

mod pcap_file;

pub use pcap_file::open_pcap_file;

use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use pcap::{Active, Capture, Device};

use crate::engine::{EngineHandle, PacketEvent};
use crate::error::{Error, Result};
use crate::filters::{bpf_expression, PacketFilter};
use crate::flow::FlowTable;
use crate::protocols::{decode_frame, DecodeResult};

pub type SharedFlows = Arc<Mutex<FlowTable>>;

fn datalink_i32(cap: &Capture<impl pcap::Activated>) -> i32 {
    cap.get_datalink().0
}

pub fn open_device(name: Option<&str>, promiscuous: bool) -> Result<Capture<Active>> {
    let device = if let Some(n) = name {
        Device::list()?
            .into_iter()
            .find(|d| d.name == n)
            .ok_or_else(|| Error::InvalidInterface(n.to_string()))?
    } else {
        Device::list()?
            .into_iter()
            .find(|d| {
                !d.name.starts_with("lo")
                    && !d.name.starts_with("docker")
                    && !d.name.starts_with("veth")
                    && d.addresses
                        .iter()
                        .any(|a| matches!(a.addr, IpAddr::V4(_) | IpAddr::V6(_)))
            })
            .or_else(|| Device::lookup().ok().flatten())
            .ok_or(Error::NoInterface)?
    };

    Ok(Capture::from_device(device)?
        .promisc(promiscuous)
        .snaplen(65535)
        .timeout(250)
        .open()?)
}

pub fn set_filter(cap: &mut Capture<Active>, filter: Option<&str>) -> Result<()> {
    cap.filter(&bpf_expression(filter), true)?;
    Ok(())
}

pub fn local_addresses(name: &str) -> Vec<IpAddr> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .find(|d| d.name == name)
        .map(|d| d.addresses.into_iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}

pub fn spawn_capture_to_engine(
    mut cap: Capture<Active>,
    engine: EngineHandle,
) -> thread::JoinHandle<()> {
    let linktype = datalink_i32(&cap);
    thread::spawn(move || loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = Instant::now();
                if let DecodeResult::Ip(ep) = decode_frame(linktype, packet.data) {
                    engine.try_send(PacketEvent {
                        src: ep.src,
                        dst: ep.dst,
                        sport: ep.src_port,
                        dport: ep.dst_port,
                        protocol: ep.protocol,
                        bytes: ep.ip_len,
                        when: now,
                        tcp: ep.tcp,
                    });
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    })
}

pub fn spawn_capture_thread(
    mut cap: Capture<Active>,
    flows: SharedFlows,
    local_addrs: Vec<IpAddr>,
    packet_filter: PacketFilter,
) -> thread::JoinHandle<()> {
    let linktype = datalink_i32(&cap);
    thread::spawn(move || loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = Instant::now();
                if let DecodeResult::Ip(ep) = decode_frame(linktype, packet.data) {
                    flows.lock().record_filtered(
                        ep.src,
                        ep.dst,
                        ep.src_port,
                        ep.dst_port,
                        ep.protocol,
                        ep.ip_len,
                        &local_addrs,
                        now,
                        &packet_filter,
                        ep.tcp,
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    })
}

use crate::flow::Aggregate;

pub fn process_pcap_file(
    path: impl AsRef<std::path::Path>,
    local_addrs: &[IpAddr],
) -> Result<FlowTable> {
    process_pcap_file_filtered(path, local_addrs, &PacketFilter::default(), Aggregate::Pair, false, None)
}

pub fn process_pcap_file_filtered(
    path: impl AsRef<std::path::Path>,
    local_addrs: &[IpAddr],
    packet_filter: &PacketFilter,
    aggregate: Aggregate,
    show_ports: bool,
    bpf_filter: Option<&str>,
) -> Result<FlowTable> {
    let mut cap = open_pcap_file(path)?;
    if let Some(f) = bpf_filter {
        if !f.trim().is_empty() {
            let _ = cap.filter(&bpf_expression(Some(f)), true);
        }
    }
    let linktype = datalink_i32(&cap);
    let mut table = FlowTable::new();
    table.set_aggregate(aggregate);
    table.set_show_ports(show_ports);
    let base_instant = Instant::now();
    let mut first_ts: Option<Duration> = None;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let pkt_sec = packet.header.ts.tv_sec as u64;
                let pkt_usec = packet.header.ts.tv_usec as u64;
                let pkt_ts = Duration::from_secs(pkt_sec) + Duration::from_micros(pkt_usec);

                let first = *first_ts.get_or_insert(pkt_ts);
                let elapsed_in_pcap = pkt_ts.saturating_sub(first);
                let when = base_instant + elapsed_in_pcap;

                if let DecodeResult::Ip(ep) = decode_frame(linktype, packet.data) {
                    table.record_filtered(
                        ep.src,
                        ep.dst,
                        ep.src_port,
                        ep.dst_port,
                        ep.protocol,
                        ep.ip_len,
                        local_addrs,
                        when,
                        packet_filter,
                        ep.tcp,
                    );
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(Error::Pcap(e)),
        }
    }
    Ok(table)
}
