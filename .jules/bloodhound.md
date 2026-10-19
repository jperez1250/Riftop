## 2025-02-18 - Non-Monotonic Instant Calculation Panics in Flow Expiration & Alerts
**Issue:** Standard `Instant::duration_since` panics at runtime if `self` is earlier than the reference `Instant`. Out-of-order packet timestamps or concurrent thread evaluation in `FlowTable::expire` and `AlertEngine::evaluate` caused panics when `now < s.last_seen` or `now < prev`.
**Fix:** Replaced `.duration_since(...)` with `.saturating_duration_since(...)`, which returns `Duration::ZERO` safely when timestamps regress instead of panicking.
**Prevention:** Always use `saturating_duration_since` when computing elapsed durations between packet or snapshot timestamps in high-concurrency or network stream domains.
