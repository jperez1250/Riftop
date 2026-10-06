## 2026-03-29 - Prevent panic on flow expiration with out-of-order/future timestamps
**Issue:** `FlowTable::expire` called `now.duration_since(s.last_seen)`, which panics at runtime if packet timestamps arrive out of order or if `now` is earlier than a flow's `last_seen` timestamp (e.g. during pcap replaying or system clock adjustments).
**Fix:** Replaced `now.duration_since(s.last_seen)` with `now.saturating_duration_since(s.last_seen)`.
**Prevention:** Always use `saturating_duration_since` when calculating elapsed time between `Instant` timestamps that may arrive out of chronological order or originate from external packet headers.
