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
    fn test_alert_engine_rate_and_pps_thresholds() {
        let now = Instant::now();
        let mut table = FlowTable::new();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Record 10,000 bytes for flow
        table.record(ip_a, ip_b, 1234, 80, 6, 10_000, &[ip_a], now, None);
        let mut snap = table.snapshot(10, now);
        snap.globals.packets_accepted = 100;

        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(500.0),
            pps: Some(50.0),
        });

        // First evaluate initializes pps last_check
        engine.evaluate(&snap, now);
        let msgs = engine.latest_messages(10);
        assert!(!msgs.is_empty(), "Expected rate alert on first evaluation");
        assert!(msgs[0].contains("RATE"), "Expected RATE alert message");

        // Second evaluation 1 second later with 100 more packets (100 pps >= 50 threshold)
        let later = now + Duration::from_secs(1);
        snap.globals.packets_accepted = 200;
        engine.evaluate(&snap, later);

        let msgs2 = engine.latest_messages(10);
        assert!(
            msgs2.iter().any(|m| m.contains("PPS")),
            "Expected PPS alert after delta evaluation"
        );
    }

    #[test]
    fn test_alert_engine_deduplication_and_max_keep() {
        let now = Instant::now();
        let mut engine = AlertEngine::new(AlertConfig::default());
        engine.max_keep = 3;

        engine.push(Alert {
            when: now,
            message: "ALERT 1".to_string(),
        });
        engine.push(Alert {
            when: now,
            message: "ALERT 1".to_string(),
        }); // Duplicate

        assert_eq!(
            engine.recent().count(),
            1,
            "Duplicate alert should be ignored"
        );

        engine.push(Alert {
            when: now,
            message: "ALERT 2".to_string(),
        });
        engine.push(Alert {
            when: now,
            message: "ALERT 3".to_string(),
        });
        engine.push(Alert {
            when: now,
            message: "ALERT 4".to_string(),
        }); // Should evict ALERT 1

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0], "ALERT 4");
        assert_eq!(msgs[1], "ALERT 3");
        assert_eq!(msgs[2], "ALERT 2");
    }
}
