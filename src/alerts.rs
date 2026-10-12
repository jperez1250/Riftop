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
    fn test_alert_engine_empty_snapshot() {
        let table = FlowTable::new();
        let now = Instant::now();
        let snap = table.snapshot(10, now);

        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(1000.0),
            pps: Some(100.0),
        });

        engine.evaluate(&snap, now);
        assert_eq!(engine.recent().count(), 0);
        assert!(engine.latest_messages(5).is_empty());
    }

    #[test]
    fn test_alert_engine_rate_threshold() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Record high throughput
        table.record(src, dst, 0, 0, 6, 50_000, &[src], t0, None);

        let snap = table.snapshot(10, t0);
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(1000.0),
            pps: None,
        });

        engine.evaluate(&snap, t0);
        assert_eq!(engine.recent().count(), 1);
        let msg = engine.latest_messages(1);
        assert_eq!(msg.len(), 1);
        assert!(msg[0].contains("RATE"));
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(50.0),
        });

        // First evaluation establishes baseline
        let snap0 = table.snapshot(10, t0);
        engine.evaluate(&snap0, t0);
        assert_eq!(engine.recent().count(), 0);

        // 1 second later, 100 packets accepted (100 PPS)
        for _ in 0..100 {
            table.record(
                src,
                dst,
                0,
                0,
                6,
                64,
                &[src],
                t0 + Duration::from_secs(1),
                None,
            );
        }
        let t1 = t0 + Duration::from_secs(1);
        let snap1 = table.snapshot(10, t1);
        engine.evaluate(&snap1, t1);

        assert_eq!(engine.recent().count(), 1);
        let msgs = engine.latest_messages(10);
        assert!(msgs[0].contains("PPS"));
    }

    #[test]
    fn test_alert_engine_deduplication() {
        let mut table = FlowTable::new();
        let t0 = Instant::now();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        table.record(src, dst, 0, 0, 6, 50_000, &[src], t0, None);
        let snap = table.snapshot(10, t0);

        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(1000.0),
            pps: None,
        });

        engine.evaluate(&snap, t0);
        assert_eq!(engine.recent().count(), 1);

        // Second evaluation with identical state should deduplicate
        engine.evaluate(&snap, t0);
        assert_eq!(engine.recent().count(), 1);
    }

    #[test]
    fn test_alert_engine_max_keep_overflow() {
        let mut engine = AlertEngine::new(AlertConfig::default());

        for i in 0..30 {
            engine.push(Alert {
                when: Instant::now(),
                message: format!("Custom Alert {i}"),
            });
        }

        // max_keep is 20
        assert_eq!(engine.recent().count(), 20);
        let msgs = engine.latest_messages(30);
        assert_eq!(msgs.len(), 20);
        assert_eq!(msgs[0], "Custom Alert 29");
        assert_eq!(msgs[19], "Custom Alert 10");
    }

    #[test]
    fn test_alert_engine_timestamp_regression() {
        let table = FlowTable::new();
        let t0 = Instant::now();
        let t_past = t0 - Duration::from_secs(10);

        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        });

        let snap = table.snapshot(10, t0);
        engine.evaluate(&snap, t0);

        // Evaluate with time regressing to t_past; should not panic due to saturating_duration_since
        engine.evaluate(&snap, t_past);
    }
}
