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
    let linktype: i32 = 1;
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
    let linktype: i32 = 1;
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

pub fn process_pcap_file(
    path: impl AsRef<std::path::Path>,
    local_addrs: &[IpAddr],
) -> Result<FlowTable> {
    process_pcap_file_filtered(path, local_addrs, &PacketFilter::default())
}

pub fn process_pcap_file_filtered(
    path: impl AsRef<std::path::Path>,
    local_addrs: &[IpAddr],
    packet_filter: &PacketFilter,
) -> Result<FlowTable> {
    let mut cap = open_pcap_file(path)?;
    let mut table = FlowTable::new();
    let base = Instant::now();
    let mut index: u64 = 0;
    let linktype: i32 = 1;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let when = base + Duration::from_secs(index);
                index += 1;
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
