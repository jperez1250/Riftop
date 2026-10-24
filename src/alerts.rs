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
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_threshold() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(a, b, 80, 443, 6, 100_000, &[a], now, None);
        let snap = table.snapshot(10, now);

        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        engine.evaluate(&snap, now);

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("RATE 10.0.0.1 ↔ 10.0.0.2"));
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(a, b, 80, 443, 6, 100, &[a], t0, None);
        let snap1 = table.snapshot(10, t0);

        let config = AlertConfig {
            rate_bps: None,
            pps: Some(5.0),
        };
        let mut engine = AlertEngine::new(config);
        engine.evaluate(&snap1, t0);

        // Record 10 packets in 1 second (10 pps > 5 pps limit)
        for _ in 0..10 {
            table.record(
                a,
                b,
                80,
                443,
                6,
                100,
                &[a],
                t0 + Duration::from_secs(1),
                None,
            );
        }
        let snap2 = table.snapshot(10, t0 + Duration::from_secs(1));
        engine.evaluate(&snap2, t0 + Duration::from_secs(1));

        let msgs = engine.latest_messages(10);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("PPS 10 >= 5"));
    }

    #[test]
    fn test_alert_engine_deduplication() {
        let mut table = FlowTable::new();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(a, b, 80, 443, 6, 100_000, &[a], now, None);
        let snap = table.snapshot(10, now);

        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        engine.evaluate(&snap, now);
        engine.evaluate(&snap, now);

        assert_eq!(
            engine.recent().count(),
            1,
            "Duplicate alert messages must be ignored"
        );
    }

    #[test]
    fn test_alert_engine_max_keep_truncation() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();
        for i in 0..30 {
            engine.push(Alert {
                when: now,
                message: format!("Alert #{i}"),
            });
        }
        assert_eq!(
            engine.recent().count(),
            20,
            "Recent alerts must be capped at max_keep (20)"
        );
        assert_eq!(engine.latest_messages(1)[0], "Alert #29");
    }

    #[test]
    fn test_alert_engine_time_regression_no_panic() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(a, b, 80, 443, 6, 100, &[a], t0, None);
        let snap = table.snapshot(10, t0);

        let config = AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        engine.evaluate(&snap, t0 + Duration::from_secs(5));

        // Evaluate with an earlier timestamp - must NOT panic
        let earlier = t0;
        engine.evaluate(&snap, earlier);
    }
}
