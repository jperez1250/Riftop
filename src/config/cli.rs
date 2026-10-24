use crate::config::mod_types::Config;

impl Config {
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

    #[must_use]
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms.unwrap_or(1000)
    }

    #[must_use]
    pub fn lines(&self) -> usize {
        self.lines.unwrap_or(20)
    }

    #[must_use]
    pub fn aggregate(&self) -> &str {
        self.aggregate.as_deref().unwrap_or("pair")
    }

    #[must_use]
    pub fn output(&self) -> &str {
        self.output.as_deref().unwrap_or("tui")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_config_cli_apply_defaults_and_overrides() {
        let mut cfg = Config::default();
        assert_eq!(cfg.interval_ms(), 1000);
        assert_eq!(cfg.lines(), 20);
        assert_eq!(cfg.aggregate(), "pair");
        assert_eq!(cfg.output(), "tui");

        cfg.apply_cli(
            &Some("eth0".to_string()),
            &Some("tcp".to_string()),
            &Some("10.0.0.0/8".to_string()),
            &None,
            &None,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            Some(500),
            Some(50),
            Some("host"),
            Some("2s"),
            Some("json"),
            Some(1000.0),
            Some(50.0),
        );

        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.filter.as_deref(), Some("tcp"));
        assert_eq!(cfg.net_filter.as_deref(), Some("10.0.0.0/8"));
        assert!(cfg.no_dns);
        assert!(cfg.no_port_resolution);
        assert!(cfg.ports);
        assert!(cfg.use_bytes);
        assert!(cfg.no_bars);
        assert!(cfg.link_local);
        assert!(cfg.promiscuous);
        assert_eq!(cfg.interval_ms(), 500);
        assert_eq!(cfg.lines(), 50);
        assert_eq!(cfg.aggregate(), "host");
        assert_eq!(cfg.output(), "json");
        assert_eq!(cfg.alert_rate_bps, Some(1000.0));
        assert_eq!(cfg.alert_pps, Some(50.0));
    }
}
