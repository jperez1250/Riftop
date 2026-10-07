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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, FlowStats, Globals, Snapshot};
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert!(config.rate_bps.is_none());
        assert!(config.pps.is_none());
    }

    #[test]
    fn test_alert_engine_rate_threshold() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let key = FlowKey::new(
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
            1234,
            80,
            6,
        );
        let mut stats = FlowStats::new(key, now);
        stats.record(now, 2000, crate::flow::Direction::Sent, None);

        let snap = Snapshot {
            flows: vec![stats],
            globals: Globals::default(),
            taken_at: now,
        };

        engine.evaluate(&snap, now);
        let alerts: Vec<_> = engine.recent().collect();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("RATE"));
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let mut globals = Globals::default();
        globals.packets_accepted = 100;

        let snap1 = Snapshot {
            flows: vec![],
            globals: globals.clone(),
            taken_at: now,
        };
        engine.evaluate(&snap1, now);
        assert_eq!(engine.recent().count(), 0);

        globals.packets_accepted = 200; // +100 pkts in 1 second = 100 pps >= 50
        let t1 = now + Duration::from_secs(1);
        let snap2 = Snapshot {
            flows: vec![],
            globals,
            taken_at: t1,
        };
        engine.evaluate(&snap2, t1);

        let alerts: Vec<_> = engine.recent().collect();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("PPS 100 >= 50"));
    }

    #[test]
    fn test_alert_engine_deduplication_and_max_keep() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        // Test deduplication
        engine.push(Alert {
            when: now,
            message: "TEST ALERT".to_string(),
        });
        engine.push(Alert {
            when: now,
            message: "TEST ALERT".to_string(),
        });
        assert_eq!(engine.recent().count(), 1);

        // Test max_keep capping at 20
        for i in 0..30 {
            engine.push(Alert {
                when: now,
                message: format!("ALERT {i}"),
            });
        }
        assert_eq!(engine.recent().count(), 20);
        let latest = engine.latest_messages(3);
        assert_eq!(latest.len(), 3);
        assert_eq!(latest[0], "ALERT 29");
        assert_eq!(latest[1], "ALERT 28");
        assert_eq!(latest[2], "ALERT 27");
    }
}
