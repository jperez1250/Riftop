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
            let elapsed = if now >= *last_ts {
                now.duration_since(*last_ts)
            } else {
                last_ts.duration_since(now)
            };
            if elapsed < Duration::from_millis(100) {
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
    fn test_rate_window_zero_max_age_does_not_panic_or_return_infinity() {
        let mut rw = RateWindow::new(Duration::ZERO);
        let now = Instant::now();
        rw.add(now, 100);
        let r = rw.rate(now);
        assert!(
            !r.is_infinite(),
            "Rate should not be infinite when max_age is zero"
        );
        assert!(!r.is_nan(), "Rate should not be NaN when max_age is zero");
        assert_eq!(r, 0.0);
    }

    #[test]
    fn test_rate_window_out_of_order_packets_do_not_merge_into_latest_sample() {
        let mut rw = RateWindow::new(Duration::from_secs(10));
        let base = Instant::now();
        let t_latest = base + Duration::from_secs(10);
        let t_old = base + Duration::from_secs(2);

        // Add a recent sample
        rw.add(t_latest, 100);
        assert_eq!(rw.samples.len(), 1);
        assert_eq!(rw.samples[0].1, 100);

        // Add an out-of-order sample that is 8 seconds older
        rw.add(t_old, 200);

        // Should create a separate sample entry instead of merging into the latest sample
        assert_eq!(rw.samples.len(), 2);
    }
}
