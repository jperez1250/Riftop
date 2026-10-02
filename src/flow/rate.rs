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
            if let Some(dur) = now.checked_duration_since(*last_ts) {
                if dur < Duration::from_millis(100) {
                    *last_bytes += bytes;
                    return;
                }
            } else {
                // Out-of-order timestamp (now < *last_ts)
                for (ts, b) in self.samples.iter_mut().rev() {
                    let diff = if *ts >= now { *ts - now } else { now - *ts };
                    if diff < Duration::from_millis(100) {
                        *b += bytes;
                        return;
                    }
                }
                let pos = self.samples.partition_point(|(ts, _)| *ts < now);
                self.samples.insert(pos, (now, bytes));
                if let Some(max_ts) = self.samples.last().map(|(ts, _)| *ts) {
                    if let Some(cutoff) = max_ts.checked_sub(self.max_age) {
                        self.samples.retain(|(ts, _)| *ts >= cutoff);
                    }
                }
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
            .filter(|(ts, _)| *ts <= now)
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
    fn test_rate_window_out_of_order_timestamp_does_not_merge_into_future_sample() {
        let base = Instant::now();
        let mut window = RateWindow::new(Duration::from_secs(2));

        // Sample 1 at t = 10.0s
        let t10 = base + Duration::from_secs(10);
        window.add(t10, 100);

        // Sample 2 at t = 2.0s (earlier timestamp, out-of-order packet)
        let t2 = base + Duration::from_secs(2);
        window.add(t2, 1000);

        // Check rate at t = 11.0s (2s window cutoff = 9.0s)
        let now = base + Duration::from_secs(11);
        let rate = window.rate(now);

        // Only t10 (100 bytes) should be included: 100 / 2.0 = 50.0 B/s.
        assert_eq!(rate, 50.0);
    }
}
