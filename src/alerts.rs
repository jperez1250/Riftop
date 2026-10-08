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
mod tests {
    use super::*;
    use crate::flow::FlowTable;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_alert_config_and_thresholds() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let mut table = FlowTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        table.record(src, dst, 1000, 80, 6, 2000, &[src], now, None);

        let snap1 = table.snapshot(10, now);
        engine.evaluate(&snap1, now);

        // First evaluate sets last_check and last_pkt_count for pps, and checks rate
        let messages = engine.latest_messages(10);
        assert!(
            !messages.is_empty(),
            "Rate alert should trigger on rate >= 100"
        );
        assert!(messages[0].starts_with("RATE "));

        // Second evaluate with 20 new packets in 1 second -> 20 pps >= 10
        let now2 = now + Duration::from_secs(1);
        for _ in 0..20 {
            table.record(src, dst, 1000, 80, 6, 100, &[src], now2, None);
        }
        let snap2 = table.snapshot(10, now2);
        engine.evaluate(&snap2, now2);

        let messages2 = engine.latest_messages(10);
        assert!(
            messages2.iter().any(|m| m.starts_with("PPS ")),
            "PPS alert should trigger when pps exceeds threshold"
        );
    }

    #[test]
    fn test_alert_deduplication_and_capacity() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: None,
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let mut table = FlowTable::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        table.record(src, dst, 1000, 80, 6, 2000, &[src], now, None);

        let snap = table.snapshot(10, now);
        engine.evaluate(&snap, now);
        let count_after_first = engine.recent().count();
        assert_eq!(count_after_first, 1);

        // Evaluate again with identical snapshot/message
        engine.evaluate(&snap, now);
        assert_eq!(
            engine.recent().count(),
            1,
            "Duplicate alert message should be ignored"
        );

        // Fill engine beyond max_keep (20) with unique alerts
        for i in 0..30 {
            let src_i = IpAddr::V4(Ipv4Addr::new(10, 0, 1, i as u8));
            table.record(src_i, dst, 1000, 80, 6, 2000, &[src_i], now, None);
            let snap_i = table.snapshot(50, now);
            engine.evaluate(&snap_i, now);
        }

        assert_eq!(
            engine.recent().count(),
            20,
            "Recent alerts queue must be capped at max_keep (20)"
        );
    }
}
