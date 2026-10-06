## 2025-05-18 - Prevent Panic DoS from Regressed Timestamps

**Vulnerability:**
Calling `Instant::duration_since` when evaluating flow expirations or rate/PPS alerts can panic if `now` is earlier than the recorded timestamp (`now < earlier`). Out-of-order network packets or system clock adjustments can cause timestamp regression, triggering an unhandled panic and Denial of Service (DoS) in the packet monitoring engine.

**Learning:**
`std::time::Instant::duration_since` panics when `self < earlier` with `'supplied instant is later than self'`. In network traffic monitoring where packet arrival timestamps or snapshot sample times can regress or arrive out of order, relying on non-saturating `duration_since` introduces crash vulnerabilities on untrusted input.

**Prevention:**
Always use `Instant::saturating_duration_since` when calculating elapsed durations between timestamps in traffic flow analysis and alert evaluation routines.
