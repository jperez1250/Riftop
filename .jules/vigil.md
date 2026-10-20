# Vigil's QA Journal

## 2025-05-18 - Stress-Testing Floating-Point Rate Calculations and DNS Cache Edge Cases
**Challenge:** Testing boundary conditions in rate calculation windows (`max_age = 0`) and DNS resolution cache where control characters or oversized hostnames can corrupt UI rendering or cause floating-point arithmetic invalidity (`NaN`).
**Strategy:** Built deterministic edge-case tests in `tests/edge_cases_suite.rs` validating rate window division boundaries, Instant duration arithmetic, network filter CIDR masks, and DNS cache input sanitization.
**Prevention:** Ensure all time-window rate math checks for zero duration before float division, and enforce UTF-8 control character sanitization and RFC 1035 length limits on external string inputs before caching or rendering.
