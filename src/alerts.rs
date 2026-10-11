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
    use crate::flow::{FlowKey, FlowStats, Snapshot};
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_bps() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        });

        let now = Instant::now();
        let key = FlowKey::new(
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            80,
            12345,
            6,
        );
        let mut flow = FlowStats::new(key, now);
        // Record enough bytes over time to exceed rate threshold
        flow.record(now, 2000, crate::flow::Direction::Sent, None);

        let snap = Snapshot {
            flows: vec![flow],
            globals: Default::default(),
            taken_at: now,
        };

        engine.evaluate(&snap, now + Duration::from_secs(1));
        let messages = engine.latest_messages(5);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("RATE"));
    }

    #[test]
    fn test_alert_engine_pps() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        });

        let t0 = Instant::now();
        let mut snap = Snapshot {
            flows: vec![],
            globals: Default::default(),
            taken_at: t0,
        };

        // First evaluation sets baseline
        snap.globals.packets_accepted = 0;
        engine.evaluate(&snap, t0);
        assert_eq!(engine.latest_messages(10).len(), 0);

        // Second evaluation 1s later with 100 packets accepted -> 100 PPS >= 50
        let t1 = t0 + Duration::from_secs(1);
        snap.globals.packets_accepted = 100;
        engine.evaluate(&snap, t1);

        let messages = engine.latest_messages(10);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("PPS 100 >= 50"));
    }

    #[test]
    fn test_alert_engine_deduplication_and_max_keep() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        });

        let mut t = Instant::now();
        let mut pkts = 0u64;

        for _ in 0..30 {
            t += Duration::from_secs(1);
            pkts += 100;
            let snap = Snapshot {
                flows: vec![],
                globals: crate::flow::Globals {
                    packets_accepted: pkts,
                    ..Default::default()
                },
                taken_at: t,
            };
            engine.evaluate(&snap, t);
        }

        // Deduplication prevents duplicate identical messages from filling queue
        // Max keep is bounded at 20
        assert!(engine.recent().count() <= 20);
    }

    #[test]
    fn test_alert_engine_time_regression() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        });

        let t0 = Instant::now();
        let snap = Snapshot {
            flows: vec![],
            globals: crate::flow::Globals {
                packets_accepted: 100,
                ..Default::default()
            },
            taken_at: t0,
        };

        engine.evaluate(&snap, t0);

        // Time regresses (now < prev)
        let t_before = t0 - Duration::from_secs(5);
        // Note: evaluating with regressed timestamp
        // If this panics, we identify a time regression vulnerability!
        engine.evaluate(&snap, t_before);
    }
}
