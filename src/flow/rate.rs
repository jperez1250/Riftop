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
mod tests {
    use super::*;

    #[test]
    fn test_rate_window_add_and_rate() {
        let mut rw = RateWindow::new(Duration::from_secs(10));
        let t0 = Instant::now();

        // Add samples 50ms apart (should merge into same 100ms bucket)
        rw.add(t0, 500);
        rw.add(t0 + Duration::from_millis(50), 500);

        assert_eq!(rw.samples.len(), 1);
        assert_eq!(rw.samples[0].1, 1000);

        // Add sample 200ms later (new bucket)
        rw.add(t0 + Duration::from_millis(250), 1000);
        assert_eq!(rw.samples.len(), 2);

        // Total 2000 bytes over 10s window -> 200 B/s
        let rate = rw.rate(t0 + Duration::from_secs(1));
        assert!((rate - 200.0).abs() < 1e-3);
    }

    #[test]
    fn test_rate_window_cutoff_pruning() {
        let mut rw = RateWindow::new(Duration::from_secs(2));
        let t0 = Instant::now();

        rw.add(t0, 1000);
        rw.add(t0 + Duration::from_secs(3), 2000);

        // First sample at t0 should have been pruned as cutoff is t0 + 1s (3s - 2s)
        assert_eq!(rw.samples.len(), 1);
        assert_eq!(rw.samples[0].1, 2000);
    }

    #[test]
    fn test_rate_window_zero_total_returns_zero() {
        let rw = RateWindow::new(Duration::from_secs(10));
        let now = Instant::now();
        assert_eq!(rw.rate(now), 0.0);
    }
}
