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
mod tests {
    use super::*;
    use crate::flow::{FlowKey, FlowStats, Globals};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_and_pps() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(50.0),
        };
        let mut engine = AlertEngine::new(config);
        let start = Instant::now();

        let mut snap = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_seen: 100,
                packets_accepted: 100,
                bytes_total: 1000,
                bytes_sent: 500,
                bytes_recv: 500,
            },
            taken_at: start,
        };

        // First check initializes last_check and last_pkt_count
        engine.evaluate(&snap, start);
        assert_eq!(engine.latest_messages(10).len(), 0);

        // Advance time by 1s and add 100 packets -> PPS = 100 >= 50 threshold
        let now = start + Duration::from_secs(1);
        snap.globals.packets_accepted = 200;

        let key = FlowKey::new(
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            1234,
            80,
            6,
        );
        let mut flow = FlowStats::new(key, start);
        // Add 2000 bytes over 1 second so rate_10s > 100 bps
        flow.record(now, 2000, crate::flow::Direction::Sent, None);
        snap.flows.push(flow);

        engine.evaluate(&snap, now);
        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 2);
        assert!(msgs.iter().any(|m| m.contains("PPS")));
        assert!(msgs.iter().any(|m| m.contains("RATE")));
    }

    #[test]
    fn test_alert_deduplication_and_max_keep() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        // Fill engine with 25 distinct alerts (max_keep = 20)
        for i in 0..25 {
            engine.push(Alert {
                when: now,
                message: format!("Alert #{i}"),
            });
        }
        assert_eq!(engine.recent().count(), 20);

        // Try pushing duplicate message
        let latest = engine.latest_messages(1)[0].clone();
        engine.push(Alert {
            when: now,
            message: latest,
        });
        assert_eq!(engine.recent().count(), 20);
    }

    #[test]
    fn test_alert_engine_regressing_timestamp_no_panic() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        });
        let t1 = Instant::now();
        let t2 = t1 + Duration::from_secs(5);

        let mut snap = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_accepted: 100,
                ..Default::default()
            },
            taken_at: t2,
        };

        engine.evaluate(&snap, t2);

        // Regressing timestamp (t1 < t2)
        snap.globals.packets_accepted = 500;
        engine.evaluate(&snap, t1); // Should use saturating_duration_since and not panic
    }
}
