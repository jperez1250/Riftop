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
    use crate::flow::{FlowKey, FlowStats, Globals, Snapshot};
    use std::net::IpAddr;
    use std::time::Duration;

    fn sample_snapshot(now: Instant, bytes: u64, packets: u64) -> Snapshot {
        let key = FlowKey::new(
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "10.0.0.2".parse::<IpAddr>().unwrap(),
            1234,
            80,
            6,
        );
        let mut stats = FlowStats::new(key, now);
        stats.record(now, bytes, crate::flow::Direction::Sent, None);

        Snapshot {
            flows: vec![stats],
            globals: Globals {
                packets_seen: packets,
                packets_accepted: packets,
                bytes_total: bytes,
                bytes_sent: bytes,
                bytes_recv: 0,
            },
            taken_at: now,
        }
    }

    #[test]
    fn test_alert_engine_rate_threshold() {
        let config = AlertConfig {
            rate_bps: Some(10.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let snap = sample_snapshot(now, 1000, 10);
        engine.evaluate(&snap, now);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("RATE 10.0.0.1 ↔ 10.0.0.2"));
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        };
        let mut engine = AlertEngine::new(config);
        let t1 = Instant::now();
        let snap1 = sample_snapshot(t1, 100, 10);
        engine.evaluate(&snap1, t1);

        let t2 = t1 + Duration::from_secs(1);
        let snap2 = sample_snapshot(t2, 200, 110);
        engine.evaluate(&snap2, t2);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("PPS 100 >= 50"));
    }

    #[test]
    fn test_alert_engine_deduplication() {
        let config = AlertConfig {
            rate_bps: Some(10.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();
        let snap = sample_snapshot(now, 1000, 10);

        engine.evaluate(&snap, now);
        engine.evaluate(&snap, now);

        assert_eq!(engine.recent().count(), 1);
    }

    #[test]
    fn test_alert_engine_max_keep_limit() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        for i in 0..30 {
            engine.push(Alert {
                when: now,
                message: format!("ALERT_{i}"),
            });
        }

        assert_eq!(engine.recent().count(), 20);
        let msgs = engine.latest_messages(5);
        assert_eq!(msgs.len(), 5);
        assert_eq!(msgs[0], "ALERT_29");
    }

    #[test]
    fn test_alert_engine_time_regression() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let t1 = Instant::now();
        let snap1 = sample_snapshot(t1, 100, 10);
        engine.evaluate(&snap1, t1);

        let t0 = t1 - Duration::from_secs(1);
        let snap0 = sample_snapshot(t0, 200, 20);
        engine.evaluate(&snap0, t0);
    }
}
