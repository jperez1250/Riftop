//! Riftop — modern iftop-style bandwidth monitor (Rust rewrite of legacy C).

mod capture;
mod cli;
mod dns;
mod error;
mod filters;
mod flow;
mod protocols;
mod services;
mod ui;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use parking_lot::Mutex;

use capture::{
    local_addresses, open_device, process_pcap_file, set_filter, spawn_capture_thread, SharedFlows,
};
use cli::Args;
use dns::DnsCache;
use filters::PacketFilter;
use flow::FlowTable;
use ui::{init_terminal, restore_terminal, run_ui, App};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(ref path) = args.pcap_file {
        let table = process_pcap_file(path, &[]).context("offline PCAP")?;
        println!("flows: {}", table.len());
        let now = std::time::Instant::now();
        for s in table.top(20, now) {
            println!(
                "{}  sent={} recv={} total={}",
                s.key.a, s.sent_bytes, s.recv_bytes, s.total_bytes
            );
        }
        return Ok(());
    }

    let mut cap = open_device(args.interface.as_deref(), args.promiscuous)
        .context("failed to open capture device (try setcap or root)")?;

    let iface_name = args.interface.clone().unwrap_or_else(|| {
        pcap::Device::list()
            .ok()
            .and_then(|devs| {
                devs.into_iter()
                    .find(|d| !d.name.starts_with("lo"))
                    .map(|d| d.name)
            })
            .unwrap_or_else(|| "unknown".into())
    });

    set_filter(&mut cap, args.filter.as_deref()).context("invalid BPF filter")?;

    let packet_filter = PacketFilter::from_options(
        args.net_filter.as_deref(),
        args.net_filter6.as_deref(),
        args.link_local,
    )
    .context("invalid net filter")?;

    let local_addrs = local_addresses(&iface_name);
    let flows: SharedFlows = Arc::new(Mutex::new(FlowTable::new()));
    let dns = Arc::new(DnsCache::new());

    let _handle = spawn_capture_thread(cap, Arc::clone(&flows), local_addrs, packet_filter);

    let mut terminal = init_terminal().context("failed to initialize terminal")?;
    let mut app = App::new(
        flows,
        dns,
        iface_name,
        args.ports,
        !args.no_dns,
        args.lines,
    );

    let result = run_ui(&mut app, &mut terminal, args.interval_ms);
    restore_terminal(&mut terminal)?;
    result.context("UI error")?;
    Ok(())
}
