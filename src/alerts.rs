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
                let dt = now.saturating_duration_since(prev).as_secs_f64().max(0.001);
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
    use crate::flow::FlowTable;
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_alert_config_default() {
        let cfg = AlertConfig::default();
        assert!(cfg.rate_bps.is_none());
        assert!(cfg.pps.is_none());
    }

    #[test]
    fn test_alert_engine_pps_evaluation() {
        let cfg = AlertConfig {
            pps: Some(100.0),
            rate_bps: None,
        };
        let mut engine = AlertEngine::new(cfg);
        let now = Instant::now();
        let mut table = FlowTable::new();

        // Initial evaluation captures baseline packet count
        let snap1 = table.snapshot(10, now);
        engine.evaluate(&snap1, now);
        assert_eq!(engine.recent().count(), 0);

        // Record 200 packets 1 second later -> 200 pps > 100 pps threshold
        let now2 = now + Duration::from_secs(1);
        for _ in 0..200 {
            table.record(
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "192.168.1.2".parse::<IpAddr>().unwrap(),
                1234,
                80,
                6,
                100,
                &[],
                now2,
                None,
            );
        }
        let snap2 = table.snapshot(10, now2);
        engine.evaluate(&snap2, now2);

        assert_eq!(engine.recent().count(), 1);
        let msgs = engine.latest_messages(1);
        assert!(!msgs.is_empty());
        assert!(msgs[0].contains("PPS 200 >= 100"));
    }

    #[test]
    fn test_alert_engine_deduplication_and_max_keep() {
        let cfg = AlertConfig {
            pps: Some(50.0),
            rate_bps: None,
        };
        let mut engine = AlertEngine::new(cfg);
        let now = Instant::now();
        let mut table = FlowTable::new();

        // Fill initial baseline
        engine.evaluate(&table.snapshot(10, now), now);

        // First interval triggers PPS alert
        let now2 = now + Duration::from_secs(1);
        for _ in 0..100 {
            table.record(
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                1234,
                80,
                6,
                100,
                &[],
                now2,
                None,
            );
        }
        engine.evaluate(&table.snapshot(10, now2), now2);
        assert_eq!(engine.recent().count(), 1);

        // Second interval with exact same packet rate triggers same message text -> deduplicated
        let now3 = now2 + Duration::from_secs(1);
        for _ in 0..100 {
            table.record(
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                1234,
                80,
                6,
                100,
                &[],
                now3,
                None,
            );
        }
        engine.evaluate(&table.snapshot(10, now3), now3);
        // Message is identical ("PPS 100 >= 50"), so count remains 1
        assert_eq!(engine.recent().count(), 1);
    }

    #[test]
    fn test_alert_engine_time_regression_safety() {
        let cfg = AlertConfig {
            pps: Some(10.0),
            rate_bps: None,
        };
        let mut engine = AlertEngine::new(cfg);
        let now = Instant::now();
        let table = FlowTable::new();

        engine.evaluate(&table.snapshot(10, now), now);

        // Simulate time moving backward (now_past < now)
        let now_past = now - Duration::from_secs(5);
        // Evaluating with regressed timestamp must not panic
        engine.evaluate(&table.snapshot(10, now_past), now_past);
    }
}
