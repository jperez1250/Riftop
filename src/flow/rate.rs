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
    fn test_rate_window_sub_100ms_accumulation() {
        let mut window = RateWindow::new(Duration::from_secs(10));
        let t0 = Instant::now();

        window.add(t0, 100);
        window.add(t0 + Duration::from_millis(50), 200);

        assert_eq!(window.samples.len(), 1);
        assert_eq!(window.samples[0].1, 300);

        let rate = window.rate(t0 + Duration::from_millis(50));
        assert!((rate - 30.0).abs() < 1e-6);
    }

    #[test]
    fn test_rate_window_cutoff_pruning() {
        let mut window = RateWindow::new(Duration::from_secs(2));
        let t0 = Instant::now();

        window.add(t0, 100);
        let t1 = t0 + Duration::from_secs(3);
        window.add(t1, 200);

        assert_eq!(window.samples.len(), 1);
        assert_eq!(window.samples[0].1, 200);
    }

    #[test]
    fn test_rate_window_zero_rate() {
        let window = RateWindow::new(Duration::from_secs(10));
        assert_eq!(window.rate(Instant::now()), 0.0);
    }
}
