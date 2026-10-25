# Vigil's Testing Journal

## 2026-03-30 - Monotonic Time-Stepping for State Engine Evaluation Testing
**Challenge:** Testing time-dependent alerts in `AlertEngine` and rate window calculations without introducing sleeping delays (`thread::sleep`) or flaky tests caused by system clock jitter.
**Strategy:** Construct synthetic test flows using `FlowTable::record` with explicit `Instant::now()` base offsets (`start + Duration::from_secs(...)`) and pass deterministic snapshot times directly into `AlertEngine::evaluate(&snapshot, eval_time)`.
**Prevention:** Always advance time deterministically via `Instant` additions in test harnesses rather than waiting on real time, ensuring fast (<1ms) and 100% deterministic test suite execution.
