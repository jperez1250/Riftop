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
    use crate::flow::{FlowTable, Globals, Snapshot};
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_threshold() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        });

        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let ip_a: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_b: IpAddr = "192.168.1.2".parse().unwrap();

        table.record(ip_a, ip_b, 1234, 80, 6, 2000, &[ip_a], t0, None);

        let snap = table.snapshot(10, t0);
        engine.evaluate(&snap, t0);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1, "Expected 1 rate alert trigger");

        // Duplicate evaluation at same instant should be de-duped
        engine.evaluate(&snap, t0);
        let msgs_after = engine.latest_messages(10);
        assert_eq!(msgs_after.len(), 1, "Duplicate alert should be suppressed");
    }

    #[test]
    fn test_alert_engine_pps_threshold_and_out_of_order_time() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        });

        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);

        let snap1 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_seen: 100,
                packets_accepted: 100,
                bytes_total: 1000,
                bytes_sent: 500,
                bytes_recv: 500,
            },
            taken_at: t0,
        };

        engine.evaluate(&snap1, t0);

        let snap2 = Snapshot {
            flows: vec![],
            globals: Globals {
                packets_seen: 200,
                packets_accepted: 200,
                bytes_total: 2000,
                bytes_sent: 1000,
                bytes_recv: 1000,
            },
            taken_at: t1,
        };

        engine.evaluate(&snap2, t1);
        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("PPS 100"));
    }

    #[test]
    fn test_alert_engine_capacity_limit() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(1.0),
            pps: None,
        });

        let t0 = Instant::now();
        for i in 0..25 {
            let mut table = FlowTable::new();
            let ip_a: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let ip_b: IpAddr = "10.0.0.254".parse().unwrap();
            table.record(ip_a, ip_b, 1000 + i as u16, 80, 6, 1000, &[ip_a], t0, None);
            let snap = table.snapshot(10, t0);
            engine.evaluate(&snap, t0);
        }

        let msgs = engine.latest_messages(30);
        assert_eq!(
            msgs.len(),
            20,
            "Alert engine should retain at most 20 recent alerts"
        );
    }
}
