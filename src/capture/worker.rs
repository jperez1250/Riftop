//! Capture worker threads and engine packet event loops.

use std::net::IpAddr;
use std::thread;
use std::time::Instant;

use pcap::{Active, Capture};

use crate::capture::datalink_i32;
use crate::capture::SharedFlows;
use crate::engine::{EngineHandle, PacketEvent};
use crate::filters::PacketFilter;
use crate::protocols::{decode_frame, DecodeResult};

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
