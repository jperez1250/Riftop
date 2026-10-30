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
    fn test_alert_engine_rate_and_pps() {
        let mut engine = AlertEngine::new(AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(10.0),
        });

        let now = Instant::now();
        let src: IpAddr = "192.168.1.1".parse().unwrap();
        let dst: IpAddr = "192.168.1.2".parse().unwrap();

        let mut table = FlowTable::new();
        table.record(src, dst, 1234, 80, 6, 2000, &[], now, None);

        let snap = table.snapshot(10, now);
        engine.evaluate(&snap, now);

        let snap2 = table.snapshot(10, now + Duration::from_secs(1));
        engine.evaluate(&snap2, now + Duration::from_secs(1));

        let recent: Vec<_> = engine.recent().collect();
        assert!(!recent.is_empty());
        let msgs = engine.latest_messages(5);
        assert_eq!(msgs.len(), recent.len());
    }

    #[test]
    fn test_alert_engine_deduplication_and_capacity() {
        let mut engine = AlertEngine::new(AlertConfig::default());

        for i in 0..30 {
            engine.push(Alert {
                when: Instant::now(),
                message: format!("Alert {i}"),
            });
        }
        assert_eq!(engine.recent().count(), 20);

        // Deduplication test
        let count_before = engine.recent().count();
        engine.push(Alert {
            when: Instant::now(),
            message: "Alert 29".to_string(),
        });
        assert_eq!(engine.recent().count(), count_before);
    }
}
