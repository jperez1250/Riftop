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
            let diff = if now >= *last_ts {
                now - *last_ts
            } else {
                *last_ts - now
            };
            if diff < Duration::from_millis(100) {
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
    fn test_rate_window_add_old_packet_does_not_merge_into_future_bucket() {
        let mut rw = RateWindow::new(Duration::from_secs(10));
        let t0 = Instant::now();
        let t10 = t0 + Duration::from_secs(10);

        rw.add(t10, 1000);
        rw.add(t0 + Duration::from_secs(5), 500);

        assert_eq!(rw.samples.len(), 2);
    }
}
