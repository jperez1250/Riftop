//! Packet capture using libpcap + etherparse.

use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use parking_lot::Mutex;
use pcap::{Active, Capture, Device};

use crate::error::{Error, Result};
use crate::flow::FlowTable;

/// Shared state updated by the capture thread.
pub type SharedFlows = Arc<Mutex<FlowTable>>;

/// Select a capture device.
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
                    && d.addresses
                        .iter()
                        .any(|a| matches!(a.addr, IpAddr::V4(_) | IpAddr::V6(_)))
            })
            .or_else(|| Device::lookup().ok().flatten())
            .ok_or(Error::NoInterface)?
    };

    let cap = Capture::from_device(device)?
        .promisc(promiscuous)
        .snaplen(65535)
        .timeout(250)
        .open()?;

    Ok(cap)
}

/// Apply an optional BPF filter.
pub fn set_filter(cap: &mut Capture<Active>, filter: Option<&str>) -> Result<()> {
    if let Some(f) = filter {
        cap.filter(f, true)?;
    }
    Ok(())
}

/// Collect local addresses of the device for direction detection.
pub fn local_addresses(name: &str) -> Vec<IpAddr> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .find(|d| d.name == name)
        .map(|d| d.addresses.into_iter().map(|a| a.addr).collect())
        .unwrap_or_default()
}

/// Spawn a background thread that continuously captures and updates the flow table.
pub fn spawn_capture_thread(
    mut cap: Capture<Active>,
    flows: SharedFlows,
    local_addrs: Vec<IpAddr>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        match cap.next_packet() {
            Ok(packet) => {
                let now = Instant::now();
                if let Some((src, dst, sport, dport, proto, len)) = parse_packet(packet.data) {
                    let mut table = flows.lock();
                    table.record(
                        src,
                        dst,
                        sport,
                        dport,
                        proto,
                        len as u64,
                        &local_addrs,
                        now,
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    })
}

/// Extract L3/L4 endpoints and frame length from a raw frame.
fn parse_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, u8, usize)> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src, dst, proto) = match sliced.ip {
        Some(InternetSlice::Ipv4(h, _)) => {
            let src = IpAddr::V4(h.source_addr());
            let dst = IpAddr::V4(h.destination_addr());
            (src, dst, h.protocol())
        }
        Some(InternetSlice::Ipv6(h, _)) => {
            let src = IpAddr::V6(h.source_addr());
            let dst = IpAddr::V6(h.destination_addr());
            (src, dst, h.next_header())
        }
        None => return None,
    };

    let (sport, dport) = match sliced.transport {
        Some(TransportSlice::Tcp(t)) => (t.source_port(), t.destination_port()),
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port()),
        _ => (0, 0),
    };

    Some((src, dst, sport, dport, proto, data.len()))
}
