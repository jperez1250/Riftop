use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RateWindow {
    samples: Vec<(Instant, u64)>,
    max_age: Duration,
}

impl RateWindow {
    #[must_use]
    pub fn new(max_age: Duration) -> Self {
        Self {
            samples: Vec::with_capacity(16),
            max_age,
        }
    }

    pub fn add(&mut self, now: Instant, bytes: u64) {
        if let Some((last_ts, last_bytes)) = self.samples.last_mut() {
            if now.saturating_duration_since(*last_ts) < Duration::from_millis(100)
                && last_ts.saturating_duration_since(now) < Duration::from_millis(100)
            {
                *last_bytes += bytes;
                return;
            }
        }
        self.samples.push((now, bytes));
        if let Some(cutoff) = now.checked_sub(self.max_age) {
            self.samples.retain(|(ts, _)| *ts >= cutoff);
        }
    }

    #[must_use]
    pub fn rate(&self, now: Instant) -> f64 {
        let cutoff = now.checked_sub(self.max_age);
        let total: u64 = self
            .samples
            .iter()
            .filter(|(ts, _)| match cutoff {
                Some(c) => *ts >= c,
                None => true,
            })
            .map(|(_, b)| *b)
            .sum();
        if total == 0 || self.max_age.is_zero() {
            return 0.0;
        }
        total as f64 / self.max_age.as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_out_of_order_packet_older_than_100ms_does_not_merge() {
        let t0 = Instant::now();
        let mut rw = RateWindow::new(Duration::from_secs(10));
        rw.add(t0 + Duration::from_secs(10), 100);

        // Out of order packet from 9 seconds ago
        rw.add(t0 + Duration::from_secs(1), 50);

        // At t0 + 20s, cutoff is t0 + 10s. The packet at t0 + 1s should expire,
        // leaving only the sample at t0 + 10s with 100 bytes (NOT 150 bytes).
        let rate_at_20s = rw.rate(t0 + Duration::from_secs(20));
        assert_eq!(rate_at_20s, 10.0);
    }

    #[test]
    fn test_zero_max_age_does_not_panic_or_nan() {
        let mut rw = RateWindow::new(Duration::ZERO);
        let t0 = Instant::now();
        rw.add(t0, 100);
        let rate = rw.rate(t0);
        assert_eq!(rate, 0.0);
    }
}
