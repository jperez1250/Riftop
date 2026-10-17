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
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_and_pps() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let t0 = Instant::now();

        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1000,
            2000,
            6,
        );
        let mut flow = FlowStats::new(key, t0);
        // Add bytes to trigger rate alert
        flow.record(t0, 2000, crate::flow::Direction::Sent, None);

        let snap = Snapshot {
            flows: vec![flow],
            globals: Globals {
                packets_seen: 100,
                packets_accepted: 100,
                bytes_total: 2000,
                bytes_sent: 2000,
                bytes_recv: 0,
            },
            taken_at: t0,
        };

        engine.evaluate(&snap, t0);

        // Next evaluation at t0 + 1s with packet count jump
        let t1 = t0 + Duration::from_secs(1);
        let snap2 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_seen: 150,
                packets_accepted: 150,
                bytes_total: 2000,
                bytes_sent: 2000,
                bytes_recv: 0,
            },
            taken_at: t1,
        };

        engine.evaluate(&snap2, t1);

        let messages = engine.latest_messages(5);
        assert!(!messages.is_empty());
        assert!(messages.iter().any(|m| m.contains("PPS")));
    }

    #[test]
    fn test_alert_engine_time_regression() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10);

        let snap = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_seen: 10,
                packets_accepted: 10,
                bytes_total: 100,
                bytes_sent: 100,
                bytes_recv: 0,
            },
            taken_at: t1,
        };

        // First evaluate set last_check to t1
        engine.evaluate(&snap, t1);

        // Second evaluate calls with t0 (where t0 < t1)
        // Testing how AlertEngine handles backward time step in now (dt calculation)
        engine.evaluate(&snap, t0);
    }
}
