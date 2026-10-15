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
    use crate::flow::{FlowKey, FlowStats, Globals};
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_alert_config_defaults() {
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
        let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_b: IpAddr = "192.168.1.2".parse().unwrap();
        let key = FlowKey::new(ip_a, ip_b, 80, 443, 6);

        let mut flow = FlowStats::new(key, now);
        // Record 10,000 bytes so rate_10s exceeds threshold (100 B/s)
        flow.record(now, 10000, crate::flow::Direction::Sent, None);

        let snap = Snapshot {
            flows: vec![flow],
            globals: Globals::default(),
            taken_at: now,
        };

        engine.evaluate(&snap, now);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("RATE 192.168.1.1"));
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        };
        let mut engine = AlertEngine::new(config);

        let now1 = Instant::now();
        let snap1 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_accepted: 10,
                ..Default::default()
            },
            taken_at: now1,
        };

        engine.evaluate(&snap1, now1);
        assert_eq!(engine.latest_messages(10).len(), 0);

        let now2 = now1 + Duration::from_secs(1);
        let snap2 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_accepted: 110, // delta = 100 pkts in 1 sec -> 100 PPS >= 50 PPS
                ..Default::default()
            },
            taken_at: now2,
        };

        engine.evaluate(&snap2, now2);
        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("PPS 100 >= 50"));
    }

    #[test]
    fn test_alert_engine_pps_time_regression() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        };
        let mut engine = AlertEngine::new(config);

        let now1 = Instant::now();
        let snap1 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_accepted: 10,
                ..Default::default()
            },
            taken_at: now1,
        };
        engine.evaluate(&snap1, now1);

        // Simulate time regression where now2 < now1
        let now2 = now1 - Duration::from_secs(5);
        let snap2 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_accepted: 2000,
                ..Default::default()
            },
            taken_at: now2,
        };

        // Must not panic due to saturating_duration_since
        engine.evaluate(&snap2, now2);
    }

    #[test]
    fn test_alert_engine_deduplication_and_max_keep() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        // Push duplicates
        for _ in 0..5 {
            engine.push(Alert {
                when: now,
                message: "DUP_ALERT".to_string(),
            });
        }
        assert_eq!(engine.latest_messages(10).len(), 1);

        // Push more than max_keep (20) distinct alerts
        for i in 0..25 {
            engine.push(Alert {
                when: now,
                message: format!("ALERT_{i}"),
            });
        }

        let msgs = engine.latest_messages(30);
        assert_eq!(msgs.len(), 20); // max_keep = 20
        assert_eq!(msgs[0], "ALERT_24"); // newest alert is front
        assert_eq!(msgs.len(), engine.recent().count());
    }
}
