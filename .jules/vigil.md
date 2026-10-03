## 2026-10-03 - Deterministic Instant Injecting for Time-Windowed Bandwidth Accounting
**Challenge:** Testing sliding rate windows (`RateWindow`), flow expirations, and threshold-based alerts (`AlertEngine`) requires testing passage of time without introducing slow or flaky `thread::sleep` calls.
**Strategy:** Inject synthetic `Instant` timestamps (`now`, `now + Duration::from_secs(...)`) directly into `add()`, `rate()`, `expire()`, and `evaluate()` method calls to simulate sub-second sample slotting, age pruning, and delta rate calculations instantly.
**Prevention:** Always maintain pure, time-injected API contracts for stateful domain structs rather than embedding internal `Instant::now()` clock reads inside calculation loops.
