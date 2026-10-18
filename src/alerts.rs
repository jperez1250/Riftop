//! Simple rate / PPS alerts (troubleshooting, not a SIEM).

use std::collections::VecDeque;
use std::time::Instant;

use crate::flow::{format_rate, Snapshot};

#[derive(Debug, Clone)]
pub struct Alert {
    pub when: Instant,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct AlertConfig {
    /// Bytes/sec (not bits) threshold for any single flow rate_10s.
    pub rate_bps: Option<f64>,
    /// Global packets/sec (accepted) threshold.
    pub pps: Option<f64>,
}

#[derive(Debug, Default)]
pub struct AlertEngine {
    pub config: AlertConfig,
    recent: VecDeque<Alert>,
    max_keep: usize,
    last_pkt_count: u64,
    last_check: Option<Instant>,
}

impl AlertEngine {
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            recent: VecDeque::with_capacity(32),
            max_keep: 20,
            last_pkt_count: 0,
            last_check: None,
        }
    }

    pub fn evaluate(&mut self, snap: &Snapshot, now: Instant) {
        if let Some(threshold) = self.config.rate_bps {
            for f in &snap.flows {
                let r = f.rate_10s(now);
                if r >= threshold {
                    self.push(Alert {
                        when: now,
                        message: format!(
                            "RATE {} \u{2194} {}  {} >= {}",
                            f.key.a,
                            f.key.b,
                            format_rate(r),
                            format_rate(threshold)
                        ),
                    });
                }
            }
        }

        if let Some(pps_lim) = self.config.pps {
            let pkts = snap.globals.packets_accepted;
            if let Some(prev) = self.last_check {
                let dt = now.duration_since(prev).as_secs_f64().max(0.001);
                let delta = pkts.saturating_sub(self.last_pkt_count) as f64;
                let pps = delta / dt;
                if pps >= pps_lim {
                    self.push(Alert {
                        when: now,
                        message: format!("PPS {pps:.0} >= {pps_lim:.0}"),
                    });
                }
            }
            self.last_pkt_count = pkts;
            self.last_check = Some(now);
        }
    }

    fn push(&mut self, alert: Alert) {
        // de-dup same message within recent window
        if self.recent.iter().any(|a| a.message == alert.message) {
            return;
        }
        self.recent.push_front(alert);
        while self.recent.len() > self.max_keep {
            self.recent.pop_back();
        }
    }

    pub fn recent(&self) -> impl Iterator<Item = &Alert> {
        self.recent.iter()
    }

    pub fn latest_messages(&self, n: usize) -> Vec<String> {
        self.recent
            .iter()
            .take(n)
            .map(|a| a.message.clone())
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::flow::{FlowTable, SortBy};
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_alert_engine_default_config_no_alerts() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let table = FlowTable::new();
        let now = Instant::now();
        let snap = table.snapshot(10, now);

        engine.evaluate(&snap, now);
        assert_eq!(engine.recent().count(), 0);
        assert!(engine.latest_messages(5).is_empty());
    }

    #[test]
    fn test_alert_engine_pps_threshold_and_dedup() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(100.0),
        });

        let start = Instant::now();
        let mut table = FlowTable::new();
        let src: IpAddr = "192.168.1.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.1".parse().unwrap();

        // Initial evaluation establishes baseline pkt_count and last_check
        let snap1 = table.snapshot_sorted(10, start, SortBy::Rate10s);
        engine.evaluate(&snap1, start);
        assert_eq!(engine.recent().count(), 0);

        // Record 500 packets over 1 second (500 pps > 100 pps threshold)
        let t1 = start + Duration::from_secs(1);
        for _ in 0..500 {
            table.record(src, dst, 1000, 80, 6, 64, &[], t1, None);
        }
        let snap2 = table.snapshot_sorted(10, t1, SortBy::Rate10s);
        engine.evaluate(&snap2, t1);

        assert_eq!(engine.recent().count(), 1);
        let msg = &engine.latest_messages(1)[0];
        assert!(msg.contains("PPS"));

        // Evaluate again with identical state: duplicate message should be de-duplicated
        engine.evaluate(&snap2, t1);
        assert_eq!(engine.recent().count(), 1);
    }

    #[test]
    fn test_alert_engine_rate_threshold_and_max_keep() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        });

        let start = Instant::now();
        let mut table = FlowTable::new();

        // Create multiple flows exceeding 100 Bps rate_10s
        for i in 1..=30 {
            let src: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let dst: IpAddr = "192.168.1.1".parse().unwrap();
            table.record(src, dst, 1000 + i as u16, 80, 6, 2000, &[], start, None);
        }

        let snap = table.snapshot_sorted(50, start, SortBy::Rate10s);
        engine.evaluate(&snap, start);

        // max_keep is 20, so recent alerts should be capped at 20
        assert!(engine.recent().count() <= 20);
        assert_eq!(engine.latest_messages(10).len(), 10);
    }

    #[test]
    fn test_alert_engine_time_regression_handling() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        });

        let start = Instant::now();
        let table = FlowTable::new();
        let snap = table.snapshot(10, start);

        // Set baseline at start
        engine.evaluate(&snap, start);

        // Evaluate at a regressed timestamp (before start)
        let regressed = start - Duration::from_secs(5);
        // Using saturating_duration_since prevents panic when timestamps regress
        engine.evaluate(&snap, regressed);
    }
}
