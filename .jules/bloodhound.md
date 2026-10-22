# Bloodhound's Journal - Critical Functional Learnings

## 2026-03-31 - Out-of-Order Packet Batching & Zero Window Rate Division
**Issue:** `now.saturating_duration_since(*last_ts)` in `RateWindow::add` returned `Duration::ZERO` when an out-of-order packet arrived with `now < *last_ts`. Because `0 < 100ms`, packets older than 100ms (e.g. 9 seconds earlier) were incorrectly merged into the latest sample bucket. Additionally, `RateWindow::rate` divided by `max_age.as_secs_f64()` without checking if `max_age` was zero, leading to `f64::INFINITY` / `NaN`.
**Fix:** Updated `RateWindow::add` to check bidirectionally (`now.saturating_duration_since(*last_ts) < 100ms && last_ts.saturating_duration_since(now) < 100ms`), and added `self.max_age.is_zero()` guard in `RateWindow::rate`. Replaced panicking `.duration_since()` calls in `FlowTable::expire` and `AlertEngine::evaluate` with `.saturating_duration_since()`.
**Prevention:** Always perform bidirectional distance checks when grouping sample buckets by time interval, and use `saturating_duration_since` when handling system/pcap packet timestamps that may regress or arrive out of order.
