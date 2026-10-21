# Bloodhound's Journal

## 2025-05-18 - Out-of-order Packet Timestamp Regressions and Panic-Free Time Calculations
**Issue:** Standard `Instant::duration_since` panics when timestamps arrive out of order or regress (e.g. packet timestamp > snapshot/expire timestamp or `now < prev`). Additionally, `now.saturating_duration_since(*last_ts)` in `RateWindow::add` evaluated to 0 when `now < *last_ts`, causing out-of-order packets older than 100ms to mistakenly merge into the latest sample bucket.
**Fix:** Updated `FlowTable::expire` and `AlertEngine::evaluate` to use `saturating_duration_since`. Updated `RateWindow::add` to calculate absolute bidirectional time differences (`if now >= *last_ts { ... } else { ... }`).
**Prevention:** Always compute bidirectional time differences or use `saturating_duration_since` when handling system clock or packet header timestamps that may be non-monotonic across threads or pcap captures.
