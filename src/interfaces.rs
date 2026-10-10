//! Interface discovery: Ethernet, VLAN, bonds, bridges; netns awareness.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use pcap::Device;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name: String,
    pub addrs: Vec<IpAddr>,
    pub kind: IfaceKind,
    pub is_up_guess: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaceKind {
    Loopback,
    Ethernet,
    Vlan,
    Bond,
    Bridge,
    Wireless,
    Virtual, // veth, docker, tun, tap
    Other,
}

impl IfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "lo",
            Self::Ethernet => "eth",
            Self::Vlan => "vlan",
            Self::Bond => "bond",
            Self::Bridge => "br",
            Self::Wireless => "wifi",
            Self::Virtual => "virt",
            Self::Other => "other",
        }
    }
}

fn classify(name: &str) -> IfaceKind {
    let n = name.to_ascii_lowercase();
    if n == "lo" || n.starts_with("lo:") {
        return IfaceKind::Loopback;
    }
    if n.contains('.') || n.starts_with("vlan") {
        return IfaceKind::Vlan;
    }
    if n.starts_with("bond") {
        return IfaceKind::Bond;
    }
    if n.starts_with("br") || n.starts_with("bridge") {
        return IfaceKind::Bridge;
    }
    if n.starts_with("wl") || n.starts_with("wlan") || n.starts_with("wifi") {
        return IfaceKind::Wireless;
    }
    if n.starts_with("veth")
        || n.starts_with("docker")
        || n.starts_with("br-")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("virbr")
        || n.starts_with("cni")
        || n.starts_with("flannel")
        || n.starts_with("cali")
    {
        return IfaceKind::Virtual;
    }
    if n.starts_with("eth") || n.starts_with("en") || n.starts_with("em") {
        return IfaceKind::Ethernet;
    }
    IfaceKind::Other
}

/// List interfaces with classification (skip pure virtual by default for auto-pick).
pub fn list_interfaces(include_virtual: bool) -> Result<Vec<IfaceInfo>> {
    let devices = Device::list().map_err(Error::Pcap)?;
    let mut out = Vec::new();
    for d in devices {
        let kind = classify(&d.name);
        if !include_virtual && matches!(kind, IfaceKind::Virtual | IfaceKind::Loopback) {
            continue;
        }
        let addrs: Vec<IpAddr> = d.addresses.iter().map(|a| a.addr).collect();
        out.push(IfaceInfo {
            name: d.name,
            addrs,
            kind,
            is_up_guess: true,
        });
    }
    Ok(out)
}

/// Prefer physical/VLAN/bond over virtual for default interface.
pub fn pick_default_interface() -> Result<String> {
    let all = list_interfaces(true)?;
    let preferred = all.iter().find(|i| {
        matches!(
            i.kind,
            IfaceKind::Ethernet | IfaceKind::Vlan | IfaceKind::Bond | IfaceKind::Wireless
        ) && !i.addrs.is_empty()
    });
    if let Some(i) = preferred {
        return Ok(i.name.clone());
    }
    all.into_iter()
        .find(|i| i.kind != IfaceKind::Loopback && !i.addrs.is_empty())
        .map(|i| i.name)
        .ok_or(Error::NoInterface)
}

/// Current network namespace inode (Linux), for display / correlation.
pub fn current_netns_id() -> Option<String> {
    let link = fs::read_link("/proc/self/ns/net").ok()?;
    Some(link.to_string_lossy().into_owned())
}

/// List network namespaces under /var/run/netns (requires privilege to enter).
pub fn list_netns_names() -> Vec<String> {
    let dir = Path::new("/var/run/netns");
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// Format a one-line summary for `--list-interfaces`.
pub fn format_iface_table(ifaces: &[IfaceInfo], netns: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(ns) = netns {
        s.push_str(&format!("netns: {ns}\n"));
    }
    s.push_str(&format!("{:<16} {:<8} {}\n", "NAME", "KIND", "ADDRESSES"));
    for i in ifaces {
        let addrs = i
            .addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "{:<16} {:<8} {}\n",
            i.name,
            i.kind.as_str(),
            if addrs.is_empty() { "-" } else { &addrs }
        ));
    }
    let names = list_netns_names();
    if !names.is_empty() {
        s.push_str("\navailable netns (use: ip netns exec NAME riftop ...):\n");
        for n in names {
            s.push_str(&format!("  {n}\n"));
        }
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_interfaces() {
        assert_eq!(classify("lo"), IfaceKind::Loopback);
        assert_eq!(classify("lo:1"), IfaceKind::Loopback);
        assert_eq!(classify("eth0"), IfaceKind::Ethernet);
        assert_eq!(classify("eno1"), IfaceKind::Ethernet);
        assert_eq!(classify("eth0.100"), IfaceKind::Vlan);
        assert_eq!(classify("vlan10"), IfaceKind::Vlan);
        assert_eq!(classify("bond0"), IfaceKind::Bond);
        assert_eq!(classify("br0"), IfaceKind::Bridge);
        assert_eq!(classify("wlan0"), IfaceKind::Wireless);
        assert_eq!(classify("veth1234"), IfaceKind::Virtual);
        assert_eq!(classify("docker0"), IfaceKind::Virtual);
        assert_eq!(classify("tun0"), IfaceKind::Virtual);
        assert_eq!(classify("custom0"), IfaceKind::Other);
    }

    #[test]
    fn test_iface_kind_as_str() {
        assert_eq!(IfaceKind::Loopback.as_str(), "lo");
        assert_eq!(IfaceKind::Ethernet.as_str(), "eth");
        assert_eq!(IfaceKind::Vlan.as_str(), "vlan");
        assert_eq!(IfaceKind::Bond.as_str(), "bond");
        assert_eq!(IfaceKind::Bridge.as_str(), "br");
        assert_eq!(IfaceKind::Wireless.as_str(), "wifi");
        assert_eq!(IfaceKind::Virtual.as_str(), "virt");
        assert_eq!(IfaceKind::Other.as_str(), "other");
    }

    #[test]
    fn test_format_iface_table() {
        let ifaces = vec![
            IfaceInfo {
                name: "eth0".to_string(),
                addrs: vec!["192.168.1.10".parse().unwrap()],
                kind: IfaceKind::Ethernet,
                is_up_guess: true,
            },
            IfaceInfo {
                name: "lo".to_string(),
                addrs: vec!["127.0.0.1".parse().unwrap()],
                kind: IfaceKind::Loopback,
                is_up_guess: true,
            },
        ];

        let formatted = format_iface_table(&ifaces, Some("testns"));
        assert!(formatted.contains("netns: testns"));
        assert!(formatted.contains("eth0"));
        assert!(formatted.contains("192.168.1.10"));
        assert!(formatted.contains("lo"));
        assert!(formatted.contains("127.0.0.1"));
    }
}
