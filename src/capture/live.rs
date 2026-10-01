#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
#![allow(clippy::all)]
//! Live packet capture device routines and BPF filtering setup.

use std::net::IpAddr;

use pcap::{Active, Capture, Device};

use crate::error::{Error, Result};
use crate::filters::bpf_expression;

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
