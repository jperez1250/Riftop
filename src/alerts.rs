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
    use crate::flow::{FlowKey, FlowStats, Globals};
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn test_alert_engine_pps_and_rate() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(10.0),
        });

        let start = Instant::now();
        let key = FlowKey::new(
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
            12345,
            80,
            6,
        );

        let mut stats = FlowStats::new(key, start);
        stats.record(
            start + Duration::from_millis(100),
            1500,
            crate::flow::Direction::Sent,
            None,
        );

        let snap = Snapshot {
            taken_at: start,
            globals: Globals {
                packets_accepted: 100,
                ..Default::default()
            },
            flows: vec![stats],
        };

        // First evaluate initializes last_check and last_pkt_count for pps, but evaluates rate
        engine.evaluate(&snap, start + Duration::from_secs(1));
        assert!(!engine.latest_messages(10).is_empty());

        let snap2 = Snapshot {
            taken_at: start + Duration::from_secs(2),
            globals: Globals {
                packets_accepted: 200,
                ..Default::default()
            },
            flows: vec![],
        };

        // Second evaluate 1s later has 100 pkts / 1s = 100 pps >= 10.0 threshold
        engine.evaluate(&snap2, start + Duration::from_secs(2));
        let msgs = engine.latest_messages(10);
        assert!(msgs.iter().any(|m| m.contains("PPS")));
    }

    #[test]
    fn test_alert_engine_deduplication() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        });

        let start = Instant::now();
        let key = FlowKey::new(
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
            12345,
            80,
            6,
        );

        let mut stats = FlowStats::new(key, start);
        stats.record(
            start + Duration::from_millis(100),
            5000,
            crate::flow::Direction::Sent,
            None,
        );

        let snap = Snapshot {
            taken_at: start,
            globals: Globals::default(),
            flows: vec![stats.clone()],
        };

        engine.evaluate(&snap, start + Duration::from_secs(1));
        let count1 = engine.recent().count();
        assert_eq!(count1, 1);

        // Evaluate again with exact same snapshot and timestamp -> same alert message should be deduplicated
        engine.evaluate(&snap, start + Duration::from_secs(1));
        let count2 = engine.recent().count();
        assert_eq!(count2, 1);
    }

    #[test]
    fn test_alert_engine_max_keep_eviction() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(1.0),
        });

        let start = Instant::now();
        let mut total_pkts = 0;
        for i in 1u64..=30u64 {
            total_pkts += i * 100;
            let snap = Snapshot {
                taken_at: start + Duration::from_secs(i),
                globals: Globals {
                    packets_accepted: total_pkts,
                    ..Default::default()
                },
                flows: vec![],
            };
            engine.evaluate(&snap, start + Duration::from_secs(i));
        }

        // Max keep is 20
        assert_eq!(engine.recent().count(), 20);
    }
}
