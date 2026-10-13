# Vigil's Testing Journal

## 2025-10-13 - Non-Panicking Packet Decoder Fuzzing & Test Lint Attributes
**Challenge:** Network packet decoders (`decode_ethernet`, `decode_frame`) process raw byte buffers across multiple data link types (DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_LINUX_SLL2). Fuzzed, truncated, or garbage input buffers could potentially cause out-of-bounds panics or integer underflow/overflow if slice indexing isn't guarded. Additionally, integration test files under `tests/` trigger Clippy errors on helper assertions (`clippy::unwrap_used`, `clippy::expect_used`) when strict workspace linting (`-D warnings`) is enforced.

**Strategy:** Constructed a deterministic fuzzer pattern iterating over buffer lengths (1..100 bytes) with pseudo-random byte patterns passed to `decode_frame` for all supported DLTs to assert zero-panic invariants under malformed payloads. Top-level test files in `tests/` were configured with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]`.

**Prevention:** Always maintain non-panicking invariant tests for packet frame decoders when introducing new LinkType support. Require top-level Clippy test allowances on integration test suites to preserve strict workspace quality gate compliance (`cargo clippy --all-targets -- -D warnings`).
