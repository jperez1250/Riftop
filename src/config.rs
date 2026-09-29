//! TOML configuration (optional file + CLI override).
//!
//! Search order:
//! 1. `--config PATH`
//! 2. `./riftop.toml`
//! 3. `$HOME/.config/riftop/config.toml`

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub interface: Option<String>,
    pub filter: Option<String>,
    pub net_filter: Option<String>,
    pub net_filter6: Option<String>,
    pub screen_filter: Option<String>,
    pub no_dns: bool,
    pub ports: bool,
    pub link_local: bool,
    pub promiscuous: bool,
    pub interval_ms: Option<u64>,
    pub lines: Option<usize>,
    pub aggregate: Option<String>,
    pub output: Option<String>,
    /// Alert when any flow rate_10s exceeds this many bytes/sec (bits if use_bits).
    pub alert_rate_bps: Option<f64>,
    /// Alert when global accepted packets/sec exceeds this.
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
    pub fn apply_cli(
        &mut self,
        interface: &Option<String>,
        filter: &Option<String>,
        net_filter: &Option<String>,
        net_filter6: &Option<String>,
        screen_filter: &Option<String>,
        no_dns: bool,
        ports: bool,
        link_local: bool,
        promiscuous: bool,
        interval_ms: u64,
        lines: usize,
        aggregate: &str,
        output: &str,
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
        if ports {
            self.ports = true;
        }
        if link_local {
            self.link_local = true;
        }
        if promiscuous {
            self.promiscuous = true;
        }
        if interval_ms != 1000 {
            self.interval_ms = Some(interval_ms);
        }
        if lines != 20 {
            self.lines = Some(lines);
        }
        if aggregate != "pair" {
            self.aggregate = Some(aggregate.to_string());
        }
        if output != "tui" {
            self.output = Some(output.to_string());
        }
        if alert_rate.is_some() {
            self.alert_rate_bps = alert_rate;
        }
        if alert_pps.is_some() {
            self.alert_pps = alert_pps;
        }
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.unwrap_or(1000)
    }

    pub fn lines(&self) -> usize {
        self.lines.unwrap_or(20)
    }

    pub fn aggregate(&self) -> &str {
        self.aggregate.as_deref().unwrap_or("pair")
    }

    pub fn output(&self) -> &str {
        self.output.as_deref().unwrap_or("tui")
    }
}

fn find_config_file() -> Option<PathBuf> {
    let local = PathBuf::from("riftop.toml");
    if local.exists() {
        return Some(local);
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".config/riftop/config.toml");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Minimal TOML-ish key=value / [section] parser (no external dep).
fn parse_file(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("config {}: {e}", path.display())))?;
    let mut cfg = Config::default();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"').trim_matches('\'');
        match key {
            "interface" => cfg.interface = Some(val.to_string()),
            "filter" | "bpf" => cfg.filter = Some(val.to_string()),
            "net_filter" | "net-filter" => cfg.net_filter = Some(val.to_string()),
            "net_filter6" | "net-filter6" => cfg.net_filter6 = Some(val.to_string()),
            "screen_filter" | "screen-filter" => cfg.screen_filter = Some(val.to_string()),
            "no_dns" | "no-dns" => cfg.no_dns = parse_bool(val),
            "ports" => cfg.ports = parse_bool(val),
            "link_local" | "link-local" => cfg.link_local = parse_bool(val),
            "promiscuous" => cfg.promiscuous = parse_bool(val),
            "interval_ms" | "interval-ms" => {
                if let Ok(n) = val.parse() {
                    cfg.interval_ms = Some(n);
                }
            }
            "lines" => {
                if let Ok(n) = val.parse() {
                    cfg.lines = Some(n);
                }
            }
            "aggregate" => cfg.aggregate = Some(val.to_string()),
            "output" => cfg.output = Some(val.to_string()),
            "alert_rate_bps" | "alert-rate-bps" => {
                if let Ok(n) = val.parse() {
                    cfg.alert_rate_bps = Some(n);
                }
            }
            "alert_pps" | "alert-pps" => {
                if let Ok(n) = val.parse() {
                    cfg.alert_pps = Some(n);
                }
            }
            _ => {}
        }
    }
    Ok(cfg)
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
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
