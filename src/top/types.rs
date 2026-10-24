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
    use std::collections::HashMap;

    #[test]
    fn test_view_mode_cycle_and_title() {
        assert_eq!(ViewMode::Flows.title(), "Top flows");
        assert_eq!(ViewMode::Flows.cycle(), ViewMode::Hosts);
        assert_eq!(ViewMode::Hosts.cycle(), ViewMode::Ports);
        assert_eq!(ViewMode::Ports.cycle(), ViewMode::Protocols);
        assert_eq!(ViewMode::Protocols.cycle(), ViewMode::Flows);
    }

    #[test]
    fn test_rank_ranking_and_truncation() {
        let mut map = HashMap::new();
        map.insert("a", (100u64, 1.0, 1.0, 1.0));
        map.insert("b", (500u64, 5.0, 5.0, 5.0));

        let ranked = rank(map, 1, |k| k.to_string());
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].label, "b");
        assert_eq!(ranked[0].bytes, 500);

        let (lbl, r2, r10, r40, b_str) = format_top_row(&ranked[0]);
        assert_eq!(lbl, "b");
        assert!(!r2.is_empty());
        assert!(!r10.is_empty());
        assert!(!r40.is_empty());
        assert!(!b_str.is_empty());
    }
}
