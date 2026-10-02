# Bloodhound Journal — Riftop Critical Bug Findings

## 2025-05-18 - RateWindow Out-Of-Order Timestamp Merging
**Issue:** `RateWindow::add` evaluated `now.saturating_duration_since(*last_ts)` to check if a packet was within 100ms of the last sample. However, for out-of-order packets where `now < *last_ts`, `saturating_duration_since` returns `Duration::ZERO`, which is less than 100ms. This caused packets with earlier timestamps to be incorrectly merged into future samples, inflating rate calculations for expired time windows.
**Fix:** Changed `RateWindow::add` to use `now.checked_duration_since(*last_ts)` to ensure samples are only merged into `last_ts` when `now >= last_ts` and within 100ms. For out-of-order timestamps (`now < last_ts`), existing sample buckets within 100ms are checked or the sample is inserted in sorted order via `partition_point`. Added `.filter(|(ts, _)| *ts <= now)` to `RateWindow::rate` to exclude future samples.
**Prevention:** Always use `checked_duration_since` or explicit ordering comparisons rather than `saturating_duration_since` when checking upper bounds on time differences in time-series data.
