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
    fn test_rate_window_sub_100ms_aggregation() {
        let mut window = RateWindow::new(Duration::from_secs(10));
        let start = Instant::now();

        window.add(start, 100);
        window.add(start + Duration::from_millis(50), 200);

        assert_eq!(window.samples.len(), 1);
        assert_eq!(window.samples[0].1, 300);
    }

    #[test]
    fn test_rate_window_eviction() {
        let mut window = RateWindow::new(Duration::from_secs(2));
        let start = Instant::now();

        window.add(start, 100);
        window.add(start + Duration::from_secs(1), 200);
        window.add(start + Duration::from_secs(3), 300);

        // First sample at `start` (t=0) should be retained if cutoff is t=3-2=1
        // sample at start (t=0) is < cutoff (t=1), so it gets removed.
        assert_eq!(window.samples.len(), 2);
    }

    #[test]
    fn test_rate_window_zero_duration() {
        let window = RateWindow::new(Duration::ZERO);
        let start = Instant::now();
        assert_eq!(window.rate(start), 0.0);
    }

    #[test]
    fn test_rate_window_empty() {
        let window = RateWindow::new(Duration::from_secs(10));
        let start = Instant::now();
        assert_eq!(window.rate(start), 0.0);
    }
}
