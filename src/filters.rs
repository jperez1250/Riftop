//! Network filters — parity with legacy iftop options.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDirection {
    Out,
    In,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetFilterV4 {
    pub network: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl NetFilterV4 {
    pub fn parse(s: &str) -> Result<Self> {
        let (net_s, mask_s) = s
            .split_once('/')
            .ok_or_else(|| Error::Other(format!("invalid net-filter (need net/mask): {s}")))?;
        let network = Ipv4Addr::from_str(net_s.trim())
            .map_err(|e| Error::Other(format!("invalid network address: {e}")))?;
        let mask = if mask_s.chars().all(|c| c.is_ascii_digit()) {
            let n: u32 = mask_s
                .parse()
                .map_err(|_| Error::Other(format!("invalid prefix length: {mask_s}")))?;
            if n > 32 {
                return Err(Error::Other(format!("prefix length > 32: {n}")));
            }
            prefix_to_mask_v4(n)
        } else {
            Ipv4Addr::from_str(mask_s.trim())
                .map_err(|e| Error::Other(format!("invalid netmask: {e}")))?
        };
        let network = Ipv4Addr::from(u32::from(network) & u32::from(mask));
        Ok(Self { network, mask })
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        (u32::from(addr) & u32::from(self.mask)) == u32::from(self.network)
    }

    pub fn classify(&self, src: Ipv4Addr, dst: Ipv4Addr) -> NetDirection {
        match (self.contains(src), self.contains(dst)) {
            (true, false) => NetDirection::Out,
            (false, true) => NetDirection::In,
            _ => NetDirection::Drop,
        }
    }
}

fn prefix_to_mask_v4(n: u32) -> Ipv4Addr {
    if n == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    if n >= 32 {
        return Ipv4Addr::BROADCAST;
    }
    Ipv4Addr::from((!0u32) << (32 - n))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetFilterV6 {
    pub network: Ipv6Addr,
    pub mask: Ipv6Addr,
}

impl NetFilterV6 {
    pub fn parse(s: &str) -> Result<Self> {
        let (net_s, mask_s) = s
            .split_once('/')
            .ok_or_else(|| Error::Other(format!("invalid net-filter6 (need net/prefix): {s}")))?;
        let network = Ipv6Addr::from_str(net_s.trim())
            .map_err(|e| Error::Other(format!("invalid IPv6 network: {e}")))?;
        let mask = if mask_s.chars().all(|c| c.is_ascii_digit()) {
            let n: u32 = mask_s
                .parse()
                .map_err(|_| Error::Other(format!("invalid prefix length: {mask_s}")))?;
            if n > 128 {
                return Err(Error::Other(format!("prefix length > 128: {n}")));
            }
            prefix_to_mask_v6(n)
        } else {
            Ipv6Addr::from_str(mask_s.trim())
                .map_err(|e| Error::Other(format!("invalid IPv6 mask: {e}")))?
        };
        let network = mask_addr_v6(network, mask);
        Ok(Self { network, mask })
    }

    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        mask_addr_v6(addr, self.mask) == self.network
    }

    pub fn classify(&self, src: Ipv6Addr, dst: Ipv6Addr) -> NetDirection {
        match (self.contains(src), self.contains(dst)) {
            (true, false) => NetDirection::Out,
            (false, true) => NetDirection::In,
            _ => NetDirection::Drop,
        }
    }
}

fn prefix_to_mask_v6(n: u32) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    let full = (n / 8) as usize;
    let rem = n % 8;
    for b in bytes.iter_mut().take(full) {
        *b = 0xff;
    }
    if rem > 0 && full < 16 {
        bytes[full] = 0xffu8 << (8 - rem);
    }
    Ipv6Addr::from(bytes)
}

fn mask_addr_v6(addr: Ipv6Addr, mask: Ipv6Addr) -> Ipv6Addr {
    let a = addr.octets();
    let m = mask.octets();
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] & m[i];
    }
    Ipv6Addr::from(out)
}

pub fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    let o = addr.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

#[derive(Debug, Clone, Default)]
pub struct PacketFilter {
    pub net4: Option<NetFilterV4>,
    pub net6: Option<NetFilterV6>,
    pub allow_link_local: bool,
}

impl PacketFilter {
    pub fn from_options(
        net4: Option<&str>,
        net6: Option<&str>,
        allow_link_local: bool,
    ) -> Result<Self> {
        Ok(Self {
            net4: net4.map(NetFilterV4::parse).transpose()?,
            net6: net6.map(NetFilterV6::parse).transpose()?,
            allow_link_local,
        })
    }

    pub fn accept(&self, src: IpAddr, dst: IpAddr) -> Option<bool> {
        if !self.allow_link_local {
            match (src, dst) {
                (IpAddr::V6(s), _) if is_link_local_v6(s) => return None,
                (_, IpAddr::V6(d)) if is_link_local_v6(d) => return None,
                _ => {}
            }
        }
        match (src, dst, &self.net4, &self.net6) {
            (IpAddr::V4(s), IpAddr::V4(d), Some(f), _) => match f.classify(s, d) {
                NetDirection::Out => Some(true),
                NetDirection::In => Some(false),
                NetDirection::Drop => None,
            },
            (IpAddr::V6(s), IpAddr::V6(d), _, Some(f)) => match f.classify(s, d) {
                NetDirection::Out => Some(true),
                NetDirection::In => Some(false),
                NetDirection::Drop => None,
            },
            (IpAddr::V4(_), IpAddr::V4(_), None, _) => Some(false),
            (IpAddr::V6(_), IpAddr::V6(_), _, None) => Some(false),
            _ => None,
        }
    }

    pub fn has_net_filter(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(_) => self.net4.is_some(),
            IpAddr::V6(_) => self.net6.is_some(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScreenFilter {
    pattern: Option<String>,
}

impl ScreenFilter {
    pub fn new(pattern: Option<String>) -> Self {
        Self {
            pattern: pattern.map(|s| s.to_lowercase()),
        }
    }

    pub fn set(&mut self, pattern: Option<String>) {
        self.pattern = pattern.map(|s| s.to_lowercase());
    }

    pub fn is_active(&self) -> bool {
        matches!(&self.pattern, Some(p) if !p.is_empty())
    }

    pub fn matches(&self, host_a: &str, host_b: &str) -> bool {
        match &self.pattern {
            None => true,
            Some(p) if p.is_empty() => true,
            Some(p) => host_a.to_lowercase().contains(p) || host_b.to_lowercase().contains(p),
        }
    }
}

pub fn bpf_expression(user: Option<&str>) -> String {
    match user {
        Some(f) if !f.trim().is_empty() => format!("({f}) and (ip or ip6)"),
        _ => "ip or ip6".to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_prefix() {
        if let Ok(f) = NetFilterV4::parse("10.0.0.0/24") {
            assert!(f.contains(Ipv4Addr::new(10, 0, 0, 5)));
            assert!(!f.contains(Ipv4Addr::new(10, 0, 1, 5)));
        } else {
            panic!("failed to parse IPv4 CIDR");
        }
    }

    #[test]
    fn test_v4_boundaries_and_mask_syntax() {
        let f0 = NetFilterV4::parse("0.0.0.0/0").unwrap();
        assert_eq!(f0.mask, Ipv4Addr::UNSPECIFIED);
        assert!(f0.contains(Ipv4Addr::new(192, 168, 1, 1)));

        let f32 = NetFilterV4::parse("192.168.1.1/32").unwrap();
        assert_eq!(f32.mask, Ipv4Addr::BROADCAST);
        assert!(f32.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!f32.contains(Ipv4Addr::new(192, 168, 1, 2)));

        let f_mask = NetFilterV4::parse("10.0.0.0/255.255.0.0").unwrap();
        assert_eq!(f_mask.mask, Ipv4Addr::new(255, 255, 0, 0));
        assert!(f_mask.contains(Ipv4Addr::new(10, 0, 5, 12)));

        assert!(NetFilterV4::parse("invalid").is_err());
        assert!(NetFilterV4::parse("10.0.0.0/33").is_err());
        assert!(NetFilterV4::parse("999.0.0.0/24").is_err());
    }

    #[test]
    fn test_v4_classify() {
        let f = NetFilterV4::parse("192.168.1.0/24").unwrap();
        let inside = Ipv4Addr::new(192, 168, 1, 10);
        let outside = Ipv4Addr::new(8, 8, 8, 8);

        assert_eq!(f.classify(inside, outside), NetDirection::Out);
        assert_eq!(f.classify(outside, inside), NetDirection::In);
        assert_eq!(f.classify(inside, inside), NetDirection::Drop);
        assert_eq!(f.classify(outside, outside), NetDirection::Drop);
    }

    #[test]
    fn test_v6_boundaries() {
        let f0 = NetFilterV6::parse("::/0").unwrap();
        assert!(f0.contains("2001:db8::1".parse().unwrap()));

        let f128 = NetFilterV6::parse("2001:db8::1/128").unwrap();
        assert!(f128.contains("2001:db8::1".parse().unwrap()));
        assert!(!f128.contains("2001:db8::2".parse().unwrap()));

        let f64 = NetFilterV6::parse("2001:db8::/64").unwrap();
        assert!(f64.contains("2001:db8::10".parse().unwrap()));
        assert!(!f64.contains("2001:db9::10".parse().unwrap()));

        assert!(NetFilterV6::parse("invalid").is_err());
        assert!(NetFilterV6::parse("2001:db8::/129").is_err());
    }

    #[test]
    fn test_is_link_local_v6() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_link_local_v6(ll));

        let non_ll: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_link_local_v6(non_ll));

        let site_local: Ipv6Addr = "fec0::1".parse().unwrap();
        assert!(!is_link_local_v6(site_local));
    }

    #[test]
    fn test_packet_filter_accept() {
        let pf =
            PacketFilter::from_options(Some("10.0.0.0/8"), Some("2001:db8::/32"), false).unwrap();

        let v4_in: IpAddr = "10.0.0.1".parse().unwrap();
        let v4_out: IpAddr = "1.1.1.1".parse().unwrap();
        let v6_ll: IpAddr = "fe80::1".parse().unwrap();

        assert_eq!(pf.accept(v4_in, v4_out), Some(true));
        assert_eq!(pf.accept(v4_out, v4_in), Some(false));
        assert_eq!(pf.accept(v4_out, v6_ll), None); // dropped because allow_link_local is false

        let pf_ll = PacketFilter::from_options(None, None, true).unwrap();
        assert_eq!(pf_ll.accept(v4_in, v4_out), Some(false));
    }

    #[test]
    fn test_screen_filter() {
        let mut filter = ScreenFilter::new(Some("Example.COM".into()));
        assert!(filter.is_active());
        assert!(filter.matches("host1.example.com", "other.net"));
        assert!(filter.matches("other.net", "HOST2.EXAMPLE.COM"));
        assert!(!filter.matches("foo.org", "bar.net"));

        filter.set(None);
        assert!(!filter.is_active());
        assert!(filter.matches("foo", "bar"));
    }

    #[test]
    fn test_bpf_expression() {
        assert_eq!(bpf_expression(None), "ip or ip6");
        assert_eq!(bpf_expression(Some("  ")), "ip or ip6");
        assert_eq!(bpf_expression(Some("port 80")), "(port 80) and (ip or ip6)");
    }
}
