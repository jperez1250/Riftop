//! Packet decoding — no statistics, no I/O.

use std::net::IpAddr;

/// Decoded endpoints for one IP packet (after L2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEndpoints {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// IP-layer length used for accounting (legacy: ipv4 total length / ipv6 plen+40).
    pub ip_len: u64,
}

/// Result of attempting to decode a raw frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeResult {
    /// Successfully decoded an IP packet of interest.
    Ip(FlowEndpoints),
    /// Frame ignored (non-IP, truncated, unsupported L2).
    Ignored,
}

/// Decode an Ethernet (or Ethernet-like) frame into flow endpoints.
///
/// Unsupported or non-IP frames return [`DecodeResult::Ignored`] — never panic.
pub fn decode_ethernet(frame: &[u8]) -> DecodeResult {
    use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

    let sliced = match SlicedPacket::from_ethernet(frame) {
        Ok(s) => s,
        Err(_) => return DecodeResult::Ignored,
    };

    let (src, dst, protocol, ip_len) = match sliced.ip {
        Some(InternetSlice::Ipv4(h, _)) => {
            let len = u64::from(h.total_len());
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                h.protocol(),
                len,
            )
        }
        Some(InternetSlice::Ipv6(h, _)) => {
            // Legacy: plen + 40
            let len = u64::from(h.payload_length()) + 40;
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                h.next_header(),
                len,
            )
        }
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
    fn empty_frame_is_ignored() {
        assert_eq!(decode_ethernet(&[]), DecodeResult::Ignored);
    }

    #[test]
    fn truncated_frame_is_ignored() {
        assert_eq!(decode_ethernet(&[0u8; 10]), DecodeResult::Ignored);
    }
}
