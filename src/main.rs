//! Riftop — modern iftop-style bandwidth monitor.

mod capture;
mod cli;
mod dns;
mod error;
mod flow;
mod ui;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use parking_lot::Mutex;

use capture::{local_addresses, open_device, set_filter, spawn_capture_thread, SharedFlows};
use cli::Args;
use dns::DnsCache;
use flow::FlowTable;
use ui::{init_terminal, restore_terminal, run_ui, App};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut cap = open_device(args.interface.as_deref(), args.promiscuous)
        .context("failed to open capture device (try running as root)")?;

    let iface_name = args
        .interface
        .clone()
        .unwrap_or_else(|| {
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

    let local_addrs = local_addresses(&iface_name);
    let flows: SharedFlows = Arc::new(Mutex::new(FlowTable::new()));
    let dns = Arc::new(DnsCache::new());

    // Start capture in background
    let _handle = spawn_capture_thread(cap, Arc::clone(&flows), local_addrs);

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
