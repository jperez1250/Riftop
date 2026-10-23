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
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_alert_engine_default() {
        let engine = AlertEngine::default();
        assert!(engine.config.rate_bps.is_none());
        assert!(engine.config.pps.is_none());
        assert_eq!(engine.recent().count(), 0);
        assert!(engine.latest_messages(5).is_empty());
    }

    #[test]
    fn test_alert_rate_threshold() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(ip_a, ip_b, 1000, 80, 6, 10_000, &[ip_a], t0, None);
        table.record(
            ip_a,
            ip_b,
            1000,
            80,
            6,
            10_000,
            &[ip_a],
            t0 + Duration::from_secs(1),
            None,
        );

        let t_eval = t0 + Duration::from_secs(1);
        let snap = table.snapshot(10, t_eval);

        let config = AlertConfig {
            rate_bps: Some(1000.0), // Total 20_000 bytes over 10s window yields 2000.0 B/s
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        engine.evaluate(&snap, t_eval);

        assert_eq!(engine.recent().count(), 1);
        let latest = engine.latest_messages(1);
        assert_eq!(latest.len(), 1);
        assert!(latest[0].contains("RATE 10.0.0.1"));
    }

    #[test]
    fn test_alert_pps_threshold() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for i in 0..100 {
            table.record(
                ip_a,
                ip_b,
                1000,
                80,
                6,
                100,
                &[ip_a],
                t0 + Duration::from_millis(i * 10),
                None,
            );
        }

        let config = AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        };
        let mut engine = AlertEngine::new(config);

        let snap1 = table.snapshot(10, t0);
        engine.evaluate(&snap1, t0);
        assert_eq!(engine.recent().count(), 0);

        let t1 = t0 + Duration::from_secs(1);
        for i in 0..100 {
            table.record(
                ip_a,
                ip_b,
                1000,
                80,
                6,
                100,
                &[ip_a],
                t1 + Duration::from_millis(i * 5),
                None,
            );
        }

        let snap2 = table.snapshot(10, t1);
        engine.evaluate(&snap2, t1);

        assert_eq!(engine.recent().count(), 1);
        let msgs = engine.latest_messages(10);
        assert!(msgs[0].contains("PPS 100 >="));
    }

    #[test]
    fn test_alert_deduplication_and_queue_bounding() {
        let config = AlertConfig {
            rate_bps: Some(10.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);

        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        table.record(ip_a, ip_b, 1000, 80, 6, 1000, &[ip_a], t0, None);

        let snap = table.snapshot(10, t0);

        // First evaluate pushes an alert
        engine.evaluate(&snap, t0);
        assert_eq!(engine.recent().count(), 1);

        // Evaluating again with identical rate duplicate message won't push duplicate
        engine.evaluate(&snap, t0);
        assert_eq!(engine.recent().count(), 1);

        // Bounding test with distinct alerts
        for i in 0..30 {
            engine.push(Alert {
                when: t0,
                message: format!("Unique alert #{i}"),
            });
        }
        assert_eq!(engine.recent().count(), 20);
        assert_eq!(engine.latest_messages(1)[0], "Unique alert #29");
    }
}
