# Vigil QA Journal: Automated Testing Patterns & Invariants

## 2025-05-18 - Stateful Alert Engine Evaluation & Bounded Queues
**Challenge:** Testing rate and PPS alert generation involves stateful delta calculations between snapshots and time steps. PPS alerts require at least two evaluations to compute `delta_pkts / dt`, where `dt` depends on monotonic `Instant` timestamps. Additionally, message deduplication and ring buffer bounds (`max_keep = 20`) require controlled message cycling.
**Strategy:** Structure deterministic timeline steps where `now` advances by explicit `Duration` increments. Verify that the initial snapshot seeds baseline packet counts without firing false PPS alerts, and subsequent snapshots trigger alerts only when delta rates exceed configured thresholds. Assert exact ring buffer capacity clamping and message deduplication behavior.
**Prevention:** Always test stateful temporal engines with synthetic deterministic `Instant` progressions rather than system clock elapsed times.
