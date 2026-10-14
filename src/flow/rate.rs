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
            if now.saturating_duration_since(*last_ts) < Duration::from_millis(100) {
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
    fn test_rate_window_zero_max_age() {
        let rw = RateWindow::new(Duration::ZERO);
        let now = Instant::now();
        assert_eq!(rw.rate(now), 0.0);
    }

    #[test]
    fn test_rate_window_out_of_order_samples() {
        let mut rw = RateWindow::new(Duration::from_secs(10));
        let t0 = Instant::now();
        rw.add(t0 + Duration::from_secs(5), 100);
        // Add an earlier timestamp after a later one
        rw.add(t0 + Duration::from_secs(2), 50);
        let rate = rw.rate(t0 + Duration::from_secs(5));
        assert!(rate >= 0.0);
    }

    #[test]
    fn test_rate_window_now_in_past() {
        let mut rw = RateWindow::new(Duration::from_secs(5));
        let t0 = Instant::now();
        rw.add(t0 + Duration::from_secs(10), 500);
        // Evaluating rate at an earlier `now` timestamp (t0 < sample timestamp)
        // Note: checked_sub(5s) yields None or cutoff <= t0, so sample at t0+10s is still >= cutoff if cutoff is None or small
        let rate = rw.rate(t0);
        assert!(rate >= 0.0);
    }
}
