//! Packet decoding — no statistics, no I/O.
//! Replaces legacy ether.h / ip.h / tcp.h / sll.h handlers.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEndpoints {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeResult {
    Ip(FlowEndpoints),
    Ignored,
}

/// Decode a raw frame given pcap data-link type (1=Ethernet, 113=Linux SLL).
pub fn decode_frame(linktype: i32, frame: &[u8]) -> DecodeResult {
    match linktype {
        1 | 12 => decode_ethernet(frame),
        113 => decode_linux_sll(frame),
        0 | 101 => {
            if frame.len() > 4 {
                decode_ip_payload(&frame[4..])
            } else {
                DecodeResult::Ignored
            }
        }
        _ => decode_ethernet(frame),
    }
}

pub fn decode_ethernet(frame: &[u8]) -> DecodeResult {
    if frame.len() < 14 {
        return DecodeResult::Ignored;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    if ethertype == 0x8100 {
        if frame.len() < 18 {
            return DecodeResult::Ignored;
        }
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        offset = 18;
    }
    if ethertype != 0x0800 && ethertype != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[offset..])
}

fn decode_linux_sll(frame: &[u8]) -> DecodeResult {
    if frame.len() < 16 {
        return DecodeResult::Ignored;
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    if protocol != 0x0800 && protocol != 0x86DD {
        return DecodeResult::Ignored;
    }
    decode_ip_payload(&frame[16..])
}

fn decode_ip_payload(payload: &[u8]) -> DecodeResult {
    use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

    let sliced = match SlicedPacket::from_ip(payload) {
        Ok(s) => s,
        Err(_) => return DecodeResult::Ignored,
    };

    let (src, dst, protocol, ip_len) = match sliced.ip {
        Some(InternetSlice::Ipv4(h, _)) => (
            IpAddr::V4(h.source_addr()),
            IpAddr::V4(h.destination_addr()),
            h.protocol(),
            u64::from(h.total_len()),
        ),
        Some(InternetSlice::Ipv6(h, _)) => (
            IpAddr::V6(h.source_addr()),
            IpAddr::V6(h.destination_addr()),
            h.next_header(),
            u64::from(h.payload_length()) + 40,
        ),
        None => return DecodeResult::Ignored,
    };

    let (src_port, dst_port) = match sliced.transport {
        Some(TransportSlice::Tcp(t)) => (t.source_port(), t.destination_port()),
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port()),
        _ => (0, 0),
    };

    DecodeResult::Ip(FlowEndpoints {
        src,
        dst,
        src_port,
        dst_port,
        protocol,
        ip_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_ignored() {
        assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
        assert_eq!(decode_frame(1, &[]), DecodeResult::Ignored);
        assert_eq!(decode_frame(113, &[0u8; 8]), DecodeResult::Ignored);
    }
}
