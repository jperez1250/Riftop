use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Aggregate {
    #[default]
    Pair,
    Source,
    Destination,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub a: IpAddr,
    pub b: IpAddr,
    pub port_a: u16,
    pub port_b: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, protocol: u8) -> Self {
        if (src, sport) <= (dst, dport) {
            Self {
                a: src,
                b: dst,
                port_a: sport,
                port_b: dport,
                protocol,
            }
        } else {
            Self {
                a: dst,
                b: src,
                port_a: dport,
                port_b: sport,
                protocol,
            }
        }
    }

    pub fn aggregate(
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        protocol: u8,
        mode: Aggregate,
        show_ports: bool,
    ) -> Self {
        match mode {
            Aggregate::Source => Self {
                a: src,
                b: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port_a: if show_ports { sport } else { 0 },
                port_b: 0,
                protocol: if show_ports { protocol } else { 0 },
            },
            Aggregate::Destination => Self {
                a: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                b: dst,
                port_a: 0,
                port_b: if show_ports { dport } else { 0 },
                protocol: if show_ports { protocol } else { 0 },
            },
            Aggregate::Pair if show_ports => Self::new(src, dst, sport, dport, protocol),
            Aggregate::Pair => Self::new(src, dst, 0, 0, 0),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_canonicalization() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let k1 = FlowKey::new(ip1, ip2, 80, 12345, 6);
        let k2 = FlowKey::new(ip2, ip1, 12345, 80, 6);

        // Symmetric endpoints produce identical canonical keys
        assert_eq!(k1, k2);
        assert_eq!(k1.a, ip1);
        assert_eq!(k1.b, ip2);
        assert_eq!(k1.port_a, 80);
        assert_eq!(k1.port_b, 12345);
    }

    #[test]
    fn test_flow_key_aggregation_modes() {
        let src: IpAddr = "192.168.1.100".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();

        // Source aggregation without ports
        let k_src = FlowKey::aggregate(src, dst, 54321, 53, 17, Aggregate::Source, false);
        assert_eq!(k_src.a, src);
        assert_eq!(k_src.b, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        assert_eq!(k_src.port_a, 0);
        assert_eq!(k_src.protocol, 0);

        // Destination aggregation with ports
        let k_dst = FlowKey::aggregate(src, dst, 54321, 53, 17, Aggregate::Destination, true);
        assert_eq!(k_dst.a, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        assert_eq!(k_dst.b, dst);
        assert_eq!(k_dst.port_b, 53);
        assert_eq!(k_dst.protocol, 17);

        // Pair aggregation without ports
        let k_pair_no_ports = FlowKey::aggregate(src, dst, 54321, 53, 17, Aggregate::Pair, false);
        assert_eq!(k_pair_no_ports.port_a, 0);
        assert_eq!(k_pair_no_ports.port_b, 0);
        assert_eq!(k_pair_no_ports.protocol, 0);
    }
}
