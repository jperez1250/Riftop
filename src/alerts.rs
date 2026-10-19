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
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_threshold() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let mut table = FlowTable::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        // Record enough bytes to exceed 100 B/s on 10s window
        table.record(ip_a, ip_b, 80, 80, 6, 2000, &[ip_a], now, None);

        let snap = table.snapshot(10, now);
        engine.evaluate(&snap, now);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("RATE"));
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(10.0), // 10 pps
        };
        let mut engine = AlertEngine::new(config);
        let start = Instant::now();

        let mut table = FlowTable::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        // Initial check at t=0 (first evaluation records last_check and last_pkt_count)
        let snap0 = table.snapshot(10, start);
        engine.evaluate(&snap0, start);
        assert_eq!(engine.latest_messages(10).len(), 0);

        // Add 100 packets 1 second later
        let t1 = start + Duration::from_secs(1);
        for _ in 0..100 {
            table.record(ip_a, ip_b, 80, 80, 6, 64, &[ip_a], t1, None);
        }

        let snap1 = table.snapshot(10, t1);
        engine.evaluate(&snap1, t1);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("PPS 100 >= 10"));
    }

    #[test]
    fn test_alert_deduplication_and_max_keep() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        // Push duplicate alert
        let alert = Alert {
            when: now,
            message: "TEST ALERT".to_string(),
        };
        engine.push(alert.clone());
        engine.push(alert.clone());
        assert_eq!(engine.recent().count(), 1);

        // Fill past max_keep (20)
        for i in 0..30 {
            engine.push(Alert {
                when: now,
                message: format!("ALERT {i}"),
            });
        }

        assert_eq!(engine.recent().count(), 20);
        let latest = engine.latest_messages(5);
        assert_eq!(latest[0], "ALERT 29");
        assert_eq!(latest[1], "ALERT 28");
    }
}
