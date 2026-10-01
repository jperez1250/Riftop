#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
//! Packet decoding — no statistics, no I/O.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub pure_ack: bool,
    pub seq: u32,
    pub payload_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEndpoints {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_len: u64,
    pub tcp: Option<TcpFlags>,
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeResult {
    Ip(FlowEndpoints),
    Ignored,
}

pub fn decode_frame(linktype: i32, frame: &[u8]) -> DecodeResult {
    match linktype {
        1 => decode_ethernet(frame),
        12 | 101 => decode_ip_payload(frame, None),
        113 => decode_linux_sll(frame),  // DLT_LINUX_SLL = 113
        276 => decode_linux_sll2(frame), // DLT_LINUX_SLL2 = 276
        0 => {
            if frame.len() > 4 {
                decode_ip_payload(&frame[4..], None)
            } else {
                DecodeResult::Ignored
            }
        }
        _ => DecodeResult::Ignored,
    }
}

pub fn decode_ethernet(frame: &[u8]) -> DecodeResult {
    if frame.len() < 14 {
        return DecodeResult::Ignored;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    let mut vlan_id = None;

    // 802.1Q and QinQ (double tag)
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < offset + 4 {
            return DecodeResult::Ignored;
        }
        let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        vlan_id = Some(tci & 0x0fff);
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    if ethertype != 0x0800 && ethertype != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[offset..], vlan_id)
}

fn decode_linux_sll(frame: &[u8]) -> DecodeResult {
    if frame.len() < 16 {
        return DecodeResult::Ignored;
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    if protocol != 0x0800 && protocol != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[16..], None)
}

fn decode_linux_sll2(frame: &[u8]) -> DecodeResult {
    if frame.len() < 20 {
        return DecodeResult::Ignored;
    }
    let protocol = u16::from_be_bytes([frame[0], frame[1]]);
    if protocol != 0x0800 && protocol != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[20..], None)
}

fn decode_ip_payload(payload: &[u8], vlan_id: Option<u16>) -> DecodeResult {
    use etherparse::{NetSlice, SlicedPacket, TransportSlice};

    let sliced = match SlicedPacket::from_ip(payload) {
        Ok(s) => s,
        Err(_) => return DecodeResult::Ignored,
    };

    let (src, dst, protocol, ip_len) = match sliced.net {
        Some(NetSlice::Ipv4(h)) => {
            let raw_len = u64::from(h.header().total_len());
            let actual_len = if raw_len == 0 {
                payload.len() as u64
            } else {
                raw_len.max(payload.len() as u64)
            };
            (
                IpAddr::V4(h.header().source_addr()),
                IpAddr::V4(h.header().destination_addr()),
                h.header().protocol().0,
                actual_len,
            )
        }
        Some(NetSlice::Ipv6(ref h)) => {
            let mut final_proto = h.header().next_header().0;
            for ext in h.extensions().clone() {
                use etherparse::Ipv6ExtensionSlice;
                match ext {
                    Ipv6ExtensionSlice::HopByHop(s) => final_proto = s.next_header().0,
                    Ipv6ExtensionSlice::Routing(s) => final_proto = s.next_header().0,
                    Ipv6ExtensionSlice::Fragment(s) => final_proto = s.next_header().0,
                    Ipv6ExtensionSlice::DestinationOptions(s) => final_proto = s.next_header().0,
                    Ipv6ExtensionSlice::Authentication(s) => final_proto = s.next_header().0,
                }
            }
            let raw_len = u64::from(h.header().payload_length()) + 40;
            let actual_len = if raw_len == 40 {
                payload.len() as u64
            } else {
                raw_len.max(payload.len() as u64)
            };
            (
                IpAddr::V6(h.header().source_addr()),
                IpAddr::V6(h.header().destination_addr()),
                final_proto,
                actual_len,
            )
        }
        None => return DecodeResult::Ignored,
    };

    let (src_port, dst_port, tcp) = match sliced.transport {
        Some(TransportSlice::Tcp(t)) => {
            let syn = t.syn();
            let ack = t.ack();
            let fin = t.fin();
            let rst = t.rst();
            let psh = t.psh();
            let payload_len = t.payload().len() as u32;
            let pure_ack = ack && !syn && !fin && !rst && payload_len == 0;
            (
                t.source_port(),
                t.destination_port(),
                Some(TcpFlags {
                    syn,
                    ack,
                    fin,
                    rst,
                    psh,
                    pure_ack,
                    seq: t.sequence_number(),
                    payload_len,
                }),
            )
        }
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port(), None),
        _ => (0, 0, None),
    };

    DecodeResult::Ip(FlowEndpoints {
        src,
        dst,
        src_port,
        dst_port,
        protocol,
        ip_len,
        tcp,
        vlan_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_ignored() {
        assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
        assert_eq!(decode_frame(1, &[]), DecodeResult::Ignored);
    }
}
