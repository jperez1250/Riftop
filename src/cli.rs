//! Command-line interface (replaces options.c / getopt).

use clap::{Parser, ValueEnum};

/// Modern iftop-style real-time bandwidth monitor.
#[derive(Debug, Parser)]
#[command(
    name = "riftop",
    version,
    about = "Display bandwidth usage on an interface by host",
    long_about = None
)]
pub struct Args {
    /// Network interface to monitor (default: first non-loopback)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// BPF filter expression (e.g. "tcp port 443")
    #[arg(short = 'f', long = "filter-code")]
    pub filter: Option<String>,

    /// Don't do hostname lookups
    #[arg(short = 'n', long = "no-dns")]
    pub no_dns: bool,

    /// Don't convert port numbers to services
    #[arg(short = 'N', long = "no-port-resolution")]
    pub no_port_resolution: bool,

    /// Show ports as well as hosts
    #[arg(short = 'P', long = "ports")]
    pub ports: bool,

    /// Run in promiscuous mode
    #[arg(short, long)]
    pub promiscuous: bool,

    /// Display bandwidth in bytes (default: bits)
    #[arg(short = 'B', long = "bytes")]
    pub use_bytes: bool,

    /// Don't display bar graph
    #[arg(short = 'b', long = "no-bars")]
    pub no_bars: bool,

    /// Count link-local IPv6 traffic
    #[arg(short = 'l', long = "link-local")]
    pub link_local: bool,

    /// IPv4 net/mask filter (show only traffic in/out of network)
    #[arg(short = 'F', long = "net-filter")]
    pub net_filter: Option<String>,

    /// Refresh interval in milliseconds
    #[arg(short = 't', long, default_value = "1000")]
    pub interval_ms: u64,

    /// Maximum number of flows to display
    #[arg(long, default_value = "20")]
    pub lines: usize,

    /// Sort column
    #[arg(long, value_enum, default_value = "10s")]
    pub sort: SortColumn,

    /// Offline PCAP file (no root required; for tests/regression)
    #[arg(long = "pcap")]
    pub pcap_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SortColumn {
    #[value(name = "2s")]
    Rate2s,
    #[value(name = "10s")]
    Rate10s,
    #[value(name = "40s")]
    Rate40s,
    Source,
    Destination,
}
