use crate::flow::{format_bytes, format_rate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewMode {
    #[default]
    Flows,
    Hosts,
    Ports,
    Protocols,
}

impl ViewMode {
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Flows => "Top flows",
            Self::Hosts => "Top hosts",
            Self::Ports => "Top ports",
            Self::Protocols => "Top protocols",
        }
    }

    #[must_use]
    pub const fn cycle(self) -> Self {
        match self {
            Self::Flows => Self::Hosts,
            Self::Hosts => Self::Ports,
            Self::Ports => Self::Protocols,
            Self::Protocols => Self::Flows,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopRow {
    pub label: String,
    pub bytes: u64,
    pub rate_2s: f64,
    pub rate_10s: f64,
    pub rate_40s: f64,
}

pub fn rank<K, F>(
    map: std::collections::HashMap<K, (u64, f64, f64, f64)>,
    n: usize,
    label: F,
) -> Vec<TopRow>
where
    F: Fn(K) -> String,
{
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    v.into_iter()
        .take(n)
        .map(|(k, (bytes, r2, r10, r40))| TopRow {
            label: label(k),
            bytes,
            rate_2s: r2,
            rate_10s: r10,
            rate_40s: r40,
        })
        .collect()
}

#[must_use]
pub fn format_top_row(row: &TopRow) -> (String, String, String, String, String) {
    (
        row.label.clone(),
        format_rate(row.rate_2s),
        format_rate(row.rate_10s),
        format_rate(row.rate_40s),
        format_bytes(row.bytes),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flow::FlowTable;
    use crate::top::{top_hosts, top_ports, top_protocols};
    use std::net::IpAddr;
    use std::time::Instant;

    #[test]
    fn test_view_mode_cycle_and_title() {
        let v = ViewMode::Flows;
        assert_eq!(v.title(), "Top flows");
        let v = v.cycle();
        assert_eq!(v, ViewMode::Hosts);
        assert_eq!(v.title(), "Top hosts");
        let v = v.cycle();
        assert_eq!(v, ViewMode::Ports);
        assert_eq!(v.title(), "Top ports");
        let v = v.cycle();
        assert_eq!(v, ViewMode::Protocols);
        assert_eq!(v.title(), "Top protocols");
        let v = v.cycle();
        assert_eq!(v, ViewMode::Flows);
    }

    #[test]
    fn test_top_aggregations() {
        let mut table = FlowTable::new();
        table.set_show_ports(true);
        let now = Instant::now();

        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        table.record(ip_a, ip_b, 80, 1001, 6, 2000, &[ip_a], now, None);

        let snap = table.snapshot(10, now);

        let hosts = top_hosts(&snap, now, 10);
        assert!(!hosts.is_empty());

        let ports = top_ports(&snap, now, 10);
        assert!(!ports.is_empty());

        let protos = top_protocols(&snap, now, 10);
        assert_eq!(protos.len(), 1);
        assert_eq!(protos[0].label, "TCP");

        let formatted = format_top_row(&protos[0]);
        assert_eq!(formatted.0, "TCP");
    }
}
