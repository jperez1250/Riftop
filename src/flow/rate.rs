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
            if now >= *last_ts && now.duration_since(*last_ts) < Duration::from_millis(100) {
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
        if self.max_age.is_zero() {
            return 0.0;
        }
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
        if total == 0 {
            return 0.0;
        }
        total as f64 / self.max_age.as_secs_f64()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_out_of_order_sample_does_not_merge() {
        let mut rw = RateWindow::new(Duration::from_secs(10));
        let t0 = Instant::now();
        rw.add(t0 + Duration::from_secs(10), 1000);
        // Packet from the past (5 seconds ago relative to latest sample)
        rw.add(t0 + Duration::from_secs(5), 500);

        // The latest sample (1000 bytes) should not have merged the 500 bytes
        assert_eq!(rw.samples[0].1, 1000);
    }

    #[test]
    fn test_zero_max_age_rate_does_not_panic_or_inf() {
        let mut rw = RateWindow::new(Duration::ZERO);
        let t0 = Instant::now();
        rw.add(t0, 1000);
        assert_eq!(rw.rate(t0), 0.0);
    }
}
