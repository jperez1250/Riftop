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
    use crate::flow::{FlowTable, SortBy};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_alert_engine_rate_and_pps() {
        let config = AlertConfig {
            rate_bps: Some(100.0),
            pps: Some(10.0),
        };
        let mut engine = AlertEngine::new(config);
        let now = Instant::now();

        let mut table = FlowTable::new();
        let ip_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Add traffic to flow
        table.record(ip_a, ip_b, 1000, 80, 6, 2000, &[ip_a], now, None);

        let snap1 = table.snapshot_sorted(10, now, SortBy::Rate10s);
        engine.evaluate(&snap1, now);

        // First PPS check sets `last_check` baseline
        assert_eq!(engine.latest_messages(5).len(), 1); // 1 rate alert

        let future = now + Duration::from_secs(1);
        let mut snap2 = table.snapshot_sorted(10, future, SortBy::Rate10s);
        snap2.globals.packets_accepted = 100; // 100 PPS delta over 1s

        engine.evaluate(&snap2, future);
        let msgs = engine.latest_messages(5);
        assert!(msgs.iter().any(|m| m.contains("PPS")));
    }

    #[test]
    fn test_alert_deduplication_and_pruning() {
        let mut engine = AlertEngine::new(AlertConfig::default());
        let now = Instant::now();

        engine.push(Alert {
            when: now,
            message: "TEST ALERT 1".to_string(),
        });
        engine.push(Alert {
            when: now,
            message: "TEST ALERT 1".to_string(),
        });
        assert_eq!(engine.latest_messages(10).len(), 1);

        for i in 0..30 {
            engine.push(Alert {
                when: now,
                message: format!("ALERT {i}"),
            });
        }
        assert_eq!(engine.recent().count(), 20); // max_keep is 20
    }
}
