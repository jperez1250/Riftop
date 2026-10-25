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
    fn test_alert_engine_default_no_alerts() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let table = FlowTable::new();
        let now = Instant::now();
        let snap = table.snapshot(10, now);

        engine.evaluate(&snap, now);
        assert_eq!(engine.recent().count(), 0);
        assert!(engine.latest_messages(5).is_empty());
    }

    #[test]
    fn test_alert_engine_rate_threshold() {
        let config = AlertConfig {
            rate_bps: Some(50.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let mut table = FlowTable::new();
        let start = Instant::now();

        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();

        // Populate flow with high byte rate in 10s window
        table.record(src, dst, 1234, 80, 6, 1000, &[src], start, None);

        let snap = table.snapshot(10, start + Duration::from_secs(1));
        engine.evaluate(&snap, start + Duration::from_secs(1));

        assert_eq!(engine.recent().count(), 1);
        let msg = &engine.latest_messages(1)[0];
        assert!(msg.contains("RATE"), "Expected RATE in message: {msg}");
        assert!(msg.contains("10.0.0.1"), "Expected IP in message: {msg}");
    }

    #[test]
    fn test_alert_engine_pps_threshold() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let mut table = FlowTable::new();
        let start = Instant::now();

        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();

        // First evaluation sets baseline
        let snap1 = table.snapshot(10, start);
        engine.evaluate(&snap1, start);
        assert_eq!(engine.recent().count(), 0);

        // Record 100 packets
        for _ in 0..100 {
            table.record(
                src,
                dst,
                1234,
                80,
                6,
                64,
                &[src],
                start + Duration::from_millis(500),
                None,
            );
        }

        let eval_time = start + Duration::from_secs(1);
        let snap2 = table.snapshot(10, eval_time);
        engine.evaluate(&snap2, eval_time);

        assert_eq!(engine.recent().count(), 1);
        let msg = &engine.latest_messages(1)[0];
        assert!(msg.contains("PPS"), "Expected PPS in message: {msg}");
    }

    #[test]
    fn test_alert_engine_deduplication() {
        let config = AlertConfig {
            rate_bps: Some(10.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let mut table = FlowTable::new();
        let start = Instant::now();

        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();

        table.record(src, dst, 1234, 80, 6, 500, &[src], start, None);

        let snap = table.snapshot(10, start);
        // Evaluate twice with identical rate/message
        engine.evaluate(&snap, start);
        engine.evaluate(&snap, start);

        assert_eq!(engine.recent().count(), 1);
    }

    #[test]
    fn test_alert_engine_max_keep() {
        let config = AlertConfig {
            rate_bps: Some(1.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let mut table = FlowTable::new();
        let start = Instant::now();

        // Create 25 unique flow alerts
        for i in 1..=25 {
            let src: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let dst: IpAddr = "10.0.0.254".parse().unwrap();
            table.record(src, dst, 1000 + i as u16, 80, 6, 1000, &[src], start, None);
        }

        let snap = table.snapshot(50, start);
        engine.evaluate(&snap, start);

        // Max keep is 20
        assert_eq!(engine.recent().count(), 20);
    }

    #[test]
    fn test_alert_engine_latest_messages_bounding() {
        let config = AlertConfig {
            rate_bps: Some(1.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let mut table = FlowTable::new();
        let start = Instant::now();

        for i in 1..=5 {
            let src: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            let dst: IpAddr = "10.0.0.254".parse().unwrap();
            table.record(src, dst, 1000 + i as u16, 80, 6, 1000, &[src], start, None);
        }

        let snap = table.snapshot(10, start);
        engine.evaluate(&snap, start);

        let msgs = engine.latest_messages(3);
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn test_alert_engine_zero_dt_handling() {
        let config = AlertConfig {
            rate_bps: None,
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let table = FlowTable::new();
        let start = Instant::now();

        let snap1 = table.snapshot(10, start);
        engine.evaluate(&snap1, start);

        // Evaluate again at the exact same instant
        let snap2 = table.snapshot(10, start);
        engine.evaluate(&snap2, start);

        // Should not panic or produce NaN/inf errors
        assert!(engine.recent().count() == 0 || engine.recent().count() == 1);
    }
}
