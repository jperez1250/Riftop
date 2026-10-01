#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::all)]
//! TOML file parsing for configuration.

#![allow(clippy::all)]

use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::config::defaults::{
    default_aggregate, default_interval_ms, default_lines, default_output, find_config_file,
};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct Config {
    pub interface: Option<String>,
    pub filter: Option<String>,
    #[serde(alias = "net-filter")]
    pub net_filter: Option<String>,
    #[serde(alias = "net-filter6")]
    pub net_filter6: Option<String>,
    #[serde(alias = "screen-filter")]
    pub screen_filter: Option<String>,
    #[serde(alias = "no-dns")]
    pub no_dns: bool,
    #[serde(alias = "no-port-resolution")]
    pub no_port_resolution: bool,
    pub ports: bool,
    #[serde(alias = "use-bytes", alias = "bytes")]
    pub use_bytes: bool,
    #[serde(alias = "no-bars")]
    pub no_bars: bool,
    #[serde(alias = "link-local")]
    pub link_local: bool,
    pub promiscuous: bool,
    #[serde(alias = "interval-ms")]
    pub interval_ms: Option<u64>,
    pub lines: Option<usize>,
    pub aggregate: Option<String>,
    pub sort: Option<String>,
    pub output: Option<String>,
    /// Alert when any flow rate_10s exceeds this many bytes/sec (bits if use_bits).
    #[serde(alias = "alert-rate-bps")]
    pub alert_rate_bps: Option<f64>,
    /// Alert when global accepted packets/sec exceeds this.
    #[serde(alias = "alert-pps")]
    pub alert_pps: Option<f64>,
}

impl Config {
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let path = if let Some(p) = explicit {
            Some(p.to_path_buf())
        } else {
            find_config_file()
        };
        match path {
            Some(p) if p.exists() => parse_file(&p),
            _ => Ok(Self::default()),
        }
    }

    /// Merge CLI non-default values over config (CLI wins).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_cli(
        &mut self,
        interface: &Option<String>,
        filter: &Option<String>,
        net_filter: &Option<String>,
        net_filter6: &Option<String>,
        screen_filter: &Option<String>,
        no_dns: bool,
        no_port_resolution: bool,
        ports: bool,
        use_bytes: bool,
        no_bars: bool,
        link_local: bool,
        promiscuous: bool,
        interval_ms: Option<u64>,
        lines: Option<usize>,
        aggregate: Option<&str>,
        sort: Option<&str>,
        output: Option<&str>,
        alert_rate: Option<f64>,
        alert_pps: Option<f64>,
    ) {
        if interface.is_some() {
            self.interface = interface.clone();
        }
        if filter.is_some() {
            self.filter = filter.clone();
        }
        if net_filter.is_some() {
            self.net_filter = net_filter.clone();
        }
        if net_filter6.is_some() {
            self.net_filter6 = net_filter6.clone();
        }
        if screen_filter.is_some() {
            self.screen_filter = screen_filter.clone();
        }
        if no_dns {
            self.no_dns = true;
        }
        if no_port_resolution {
            self.no_port_resolution = true;
        }
        if ports {
            self.ports = true;
        }
        if use_bytes {
            self.use_bytes = true;
        }
        if no_bars {
            self.no_bars = true;
        }
        if link_local {
            self.link_local = true;
        }
        if promiscuous {
            self.promiscuous = true;
        }
        if let Some(v) = interval_ms {
            self.interval_ms = Some(v);
        }
        if let Some(v) = lines {
            self.lines = Some(v);
        }
        if let Some(v) = aggregate {
            self.aggregate = Some(v.to_string());
        }
        if let Some(v) = sort {
            self.sort = Some(v.to_string());
        }
        if let Some(v) = output {
            self.output = Some(v.to_string());
        }
        if alert_rate.is_some() {
            self.alert_rate_bps = alert_rate;
        }
        if alert_pps.is_some() {
            self.alert_pps = alert_pps;
        }
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.unwrap_or_else(default_interval_ms)
    }

    pub fn lines(&self) -> usize {
        self.lines.unwrap_or_else(default_lines)
    }

    pub fn aggregate(&self) -> &str {
        self.aggregate
            .as_deref()
            .unwrap_or_else(|| default_aggregate())
    }

    pub fn output(&self) -> &str {
        self.output
            .as_deref()
            .unwrap_or_else(|| default_output())
    }
}

pub fn parse_file(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("config {}: {e}", path.display())))?;
    toml::from_str(&text).map_err(|e| Error::Other(format!("config {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample() {
        let dir = std::env::temp_dir().join("riftop_cfg_test");
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("t.toml");
        fs::write(
            &p,
            r#"
interface = "eth0"
filter = "tcp port 443"
ports = true
alert_rate_bps = 125000000
# comment
"#,
        )
        .unwrap();
        let c = parse_file(&p).unwrap();
        assert_eq!(c.interface.as_deref(), Some("eth0"));
        assert_eq!(c.filter.as_deref(), Some("tcp port 443"));
        assert!(c.ports);
        assert_eq!(c.alert_rate_bps, Some(125_000_000.0));
        let _ = fs::remove_file(&p);
    }
}
