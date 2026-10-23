//! Command-line interface (replaces options.c / getopt).

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "riftop",
    version,
    about = "Display bandwidth usage on an interface by host",
    long_about = None
)]
pub struct Args {
    #[arg(short, long)]
    pub interface: Option<String>,

    #[arg(short = 'f', long = "filter-code")]
    pub filter: Option<String>,

    #[arg(short = 'n', long = "no-dns")]
    pub no_dns: bool,

    #[arg(short = 'N', long = "no-port-resolution")]
    pub no_port_resolution: bool,

    #[arg(short = 'P', long = "ports")]
    pub ports: bool,

    #[arg(short, long)]
    pub promiscuous: bool,

    #[arg(short = 'B', long = "bytes")]
    pub use_bytes: bool,

    #[arg(short = 'b', long = "no-bars")]
    pub no_bars: bool,

    #[arg(short = 'l', long = "link-local")]
    pub link_local: bool,

    #[arg(short = 'F', long = "net-filter")]
    pub net_filter: Option<String>,

    #[arg(short = 'G', long = "net-filter6")]
    pub net_filter6: Option<String>,

    #[arg(long = "screen-filter")]
    pub screen_filter: Option<String>,

    #[arg(short = 't', long)]
    pub interval_ms: Option<u64>,

    #[arg(long)]
    pub lines: Option<usize>,

    #[arg(long, value_enum)]
    pub sort: Option<SortColumn>,

    #[arg(long = "pcap")]
    pub pcap_file: Option<String>,

    #[arg(long = "output")]
    pub output: Option<String>,

    #[arg(long = "aggregate")]
    pub aggregate: Option<String>,

    #[arg(long = "config")]
    pub config: Option<String>,

    #[arg(long = "alert-rate-bps")]
    pub alert_rate_bps: Option<f64>,

    #[arg(long = "alert-pps")]
    pub alert_pps: Option<f64>,

    /// List interfaces (kind, addrs) and netns, then exit
    #[arg(long = "list-interfaces")]
    pub list_interfaces: bool,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_defaults() {
        let args = Args::try_parse_from(["riftop"]).unwrap();
        assert!(args.interface.is_none());
        assert!(!args.no_dns);
        assert!(!args.no_port_resolution);
        assert!(!args.ports);
        assert!(!args.promiscuous);
        assert!(!args.use_bytes);
        assert!(!args.no_bars);
        assert!(!args.link_local);
        assert!(args.sort.is_none());
        assert!(!args.list_interfaces);
    }

    #[test]
    fn test_cli_parse_flags() {
        let args = Args::try_parse_from([
            "riftop",
            "-i",
            "eth0",
            "-n",
            "-N",
            "-P",
            "-p",
            "-B",
            "-b",
            "-l",
            "--list-interfaces",
        ])
        .unwrap();

        assert_eq!(args.interface.as_deref(), Some("eth0"));
        assert!(args.no_dns);
        assert!(args.no_port_resolution);
        assert!(args.ports);
        assert!(args.promiscuous);
        assert!(args.use_bytes);
        assert!(args.no_bars);
        assert!(args.link_local);
        assert!(args.list_interfaces);
    }

    #[test]
    fn test_cli_parse_options() {
        let args = Args::try_parse_from([
            "riftop",
            "-f",
            "tcp port 80",
            "-F",
            "10.0.0.0/8",
            "-G",
            "2001:db8::/32",
            "--screen-filter",
            "cdn",
            "-t",
            "1000",
            "--lines",
            "25",
            "--sort",
            "10s",
            "--pcap",
            "sample.pcap",
            "--output",
            "json",
            "--aggregate",
            "pair",
            "--alert-rate-bps",
            "100000.0",
            "--alert-pps",
            "500.0",
        ])
        .unwrap();

        assert_eq!(args.filter.as_deref(), Some("tcp port 80"));
        assert_eq!(args.net_filter.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(args.net_filter6.as_deref(), Some("2001:db8::/32"));
        assert_eq!(args.screen_filter.as_deref(), Some("cdn"));
        assert_eq!(args.interval_ms, Some(1000));
        assert_eq!(args.lines, Some(25));
        assert_eq!(args.sort, Some(SortColumn::Rate10s));
        assert_eq!(args.pcap_file.as_deref(), Some("sample.pcap"));
        assert_eq!(args.output.as_deref(), Some("json"));
        assert_eq!(args.aggregate.as_deref(), Some("pair"));
        assert_eq!(args.alert_rate_bps, Some(100000.0));
        assert_eq!(args.alert_pps, Some(500.0));
    }

    #[test]
    fn test_cli_sort_column_enum() {
        let args2s = Args::try_parse_from(["riftop", "--sort", "2s"]).unwrap();
        assert_eq!(args2s.sort, Some(SortColumn::Rate2s));

        let args40s = Args::try_parse_from(["riftop", "--sort", "40s"]).unwrap();
        assert_eq!(args40s.sort, Some(SortColumn::Rate40s));

        let args_src = Args::try_parse_from(["riftop", "--sort", "source"]).unwrap();
        assert_eq!(args_src.sort, Some(SortColumn::Source));

        let args_dst = Args::try_parse_from(["riftop", "--sort", "destination"]).unwrap();
        assert_eq!(args_dst.sort, Some(SortColumn::Destination));
    }
}
