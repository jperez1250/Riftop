## 2025-02-18 - Prevent Panics on Monotonic Timestamp Regressions in Evaluation Windows

**Challenge:**
Network packet capturing environments or offline PCAP replays can present timestamps out of order or evaluate rate windows/alerts at earlier `Instant` values (timestamp regression), causing runtime panics when calling standard `Instant::duration_since`.

**Strategy:**
In evaluation loops (such as `FlowTable::expire` or `AlertEngine::evaluate`), replace `Instant::duration_since` with `Instant::saturating_duration_since`. Write dedicated unit tests using time-shifted `Instant` values (`t0` vs `t0 + dt`) to assert that non-monotonic timestamp inputs execute gracefully without panicking.

**Prevention:**
Always use `saturating_duration_since` when computing delta time intervals across packet arrival timestamps or async evaluation frames.
