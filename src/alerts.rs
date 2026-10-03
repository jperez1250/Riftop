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
    fn test_alert_engine_rate_and_pps_thresholds() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let mut table = FlowTable::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Initial snapshot at t0
        table.record(ip1, ip2, 1234, 80, 6, 2000, &[ip1], now, None);
        let snap1 = table.snapshot(10, now);

        // Evaluate t0
        engine.evaluate(&snap1, now);
        let msgs = engine.latest_messages(5);
        assert!(!msgs.is_empty());
        assert!(msgs[0].contains("RATE 10.0.0.1"));

        // Evaluate t1 (1 sec later, 20 accepted packets delta = 20 pps > 10 pps limit)
        let later = now + Duration::from_secs(1);
        for _ in 0..20 {
            table.record(ip1, ip2, 1234, 80, 6, 100, &[ip1], later, None);
        }
        let snap2 = table.snapshot(10, later);
        engine.evaluate(&snap2, later);

        let msgs2 = engine.latest_messages(5);
        assert!(msgs2.iter().any(|m| m.contains("PPS 20 >= 10")));
    }

    #[test]
    fn test_alert_deduplication() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        engine.push(Alert {
            when: now,
            message: "Test Alert".to_string(),
        });
        engine.push(Alert {
            when: now,
            message: "Test Alert".to_string(),
        });

        assert_eq!(engine.latest_messages(10).len(), 1);
    }
}
