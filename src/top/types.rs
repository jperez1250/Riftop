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

    #[test]
    fn test_view_mode_methods() {
        assert_eq!(ViewMode::Flows.title(), "Top flows");
        assert_eq!(ViewMode::Hosts.title(), "Top hosts");
        assert_eq!(ViewMode::Ports.title(), "Top ports");
        assert_eq!(ViewMode::Protocols.title(), "Top protocols");

        assert_eq!(ViewMode::Flows.cycle(), ViewMode::Hosts);
        assert_eq!(ViewMode::Hosts.cycle(), ViewMode::Ports);
        assert_eq!(ViewMode::Ports.cycle(), ViewMode::Protocols);
        assert_eq!(ViewMode::Protocols.cycle(), ViewMode::Flows);
    }

    #[test]
    fn test_format_top_row() {
        let row = TopRow {
            label: "10.0.0.1".to_string(),
            bytes: 1048576,
            rate_2s: 100.0,
            rate_10s: 200.0,
            rate_40s: 300.0,
        };
        let formatted = format_top_row(&row);
        assert_eq!(formatted.0, "10.0.0.1");
        assert_eq!(formatted.4, "1.00 MB");
    }
}
