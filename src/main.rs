//! Riftop — modern iftop-style bandwidth monitor (Rust rewrite of legacy C).

mod capture;
mod cli;
mod dns;
mod engine;
mod error;
mod export;
mod filters;
mod flow;
mod privileges;
mod protocols;
mod services;
mod top;
mod ui;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use parking_lot::Mutex;

use capture::{
    local_addresses, open_device, process_pcap_file, set_filter, spawn_capture_to_engine, SharedFlows,
};
use cli::Args;
use dns::DnsCache;
use engine::spawn_engine;
use export::{write_csv, write_json, write_text, OutputFormat};
use filters::{PacketFilter, ScreenFilter};
use flow::{Aggregate, FlowTable};
use privileges::warn_if_root;
use ui::{init_terminal, restore_terminal, run_ui, App};

fn parse_aggregate(s: &str) -> Aggregate {
    match s.to_ascii_lowercase().as_str() {
        "src" | "source" => Aggregate::Source,
        "dst" | "destination" => Aggregate::Destination,
        _ => Aggregate::Pair,
    }
}

fn main() -> anyhow::Result<()> {
    let _ = warn_if_root(&mut std::io::stderr());

    let args = Args::parse();
    let output = OutputFormat::parse(&args.output);
    let aggregate = parse_aggregate(&args.aggregate);

    if let Some(ref path) = args.pcap_file {
        let mut table = process_pcap_file(path, &[]).context("offline PCAP")?;
        table.set_aggregate(aggregate);
        table.set_show_ports(args.ports);
        let now = std::time::Instant::now();

        match output {
            OutputFormat::Json => {
                write_json(&mut std::io::stdout(), &table, now, args.lines, path)?;
                return Ok(());
            }
            OutputFormat::Text => {
                write_text(&mut std::io::stdout(), &table, now, args.lines)?;
                return Ok(());
            }
            OutputFormat::Csv => {
                write_csv(&mut std::io::stdout(), &table, now, args.lines)?;
                return Ok(());
            }
            OutputFormat::Tui => {
                let flows: SharedFlows = Arc::new(Mutex::new(table));
                let dns = Arc::new(DnsCache::new());
                let mut terminal = init_terminal().context("terminal")?;
                let mut app = App::new(
                    flows,
                    dns,
                    path.clone(),
                    args.ports,
                    !args.no_dns,
                    args.lines,
                );
                app.offline = true;
                app.aggregate = aggregate;
                app.screen_filter = ScreenFilter::new(args.screen_filter);
                app.capture_filter = args.filter.clone();
                let result = run_ui(&mut app, &mut terminal, args.interval_ms);
                restore_terminal(&mut terminal)?;
                result.context("UI error")?;
                return Ok(());
            }
        }
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
    let mut table = FlowTable::new();
    table.set_aggregate(aggregate);
    table.set_show_ports(args.ports);
    let flows: SharedFlows = Arc::new(Mutex::new(table));
    let dns = Arc::new(DnsCache::new());

    // Bounded channel: capture → engine → FlowTable
    let engine = spawn_engine(Arc::clone(&flows), local_addrs, packet_filter, None);
    let dropped = Arc::clone(&engine.dropped);
    let _cap_handle = spawn_capture_to_engine(cap, engine);

    if matches!(output, OutputFormat::Json | OutputFormat::Text | OutputFormat::Csv) {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let table = flows.lock();
        let now = std::time::Instant::now();
        match output {
            OutputFormat::Json => write_json(&mut std::io::stdout(), &table, now, args.lines, &iface_name)?,
            OutputFormat::Text => write_text(&mut std::io::stdout(), &table, now, args.lines)?,
            OutputFormat::Csv => write_csv(&mut std::io::stdout(), &table, now, args.lines)?,
            OutputFormat::Tui => {}
        }
        return Ok(());
    }

    let mut terminal = init_terminal().context("failed to initialize terminal")?;
    let mut app = App::new(
        flows,
        dns,
        iface_name,
        args.ports,
        !args.no_dns,
        args.lines,
    );
    app.aggregate = aggregate;
    app.screen_filter = ScreenFilter::new(args.screen_filter);
    app.capture_filter = args.filter.clone();
    app.dropped = Some(dropped);

    let result = run_ui(&mut app, &mut terminal, args.interval_ms);
    restore_terminal(&mut terminal)?;
    result.context("UI error")?;
    Ok(())
}
