//! Command-line interface.

use clap::Parser;

/// Modern iftop-style real-time bandwidth monitor.
#[derive(Debug, Parser)]
#[command(name = "riftop", version, about, long_about = None)]
pub struct Args {
    /// Network interface to monitor (default: first non-loopback)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// BPF filter expression (e.g. "tcp port 443")
    #[arg(short = 'f', long)]
    pub filter: Option<String>,

    /// Disable reverse DNS resolution
    #[arg(short = 'n', long)]
    pub no_dns: bool,

    /// Show port numbers
    #[arg(short = 'P', long)]
    pub ports: bool,

    /// Promiscuous mode
    #[arg(short, long)]
    pub promiscuous: bool,

    /// Refresh interval in milliseconds
    #[arg(short = 't', long, default_value = "1000")]
    pub interval_ms: u64,

    /// Maximum number of flows to display
    #[arg(short = 'l', long, default_value = "20")]
    pub lines: usize,
}
