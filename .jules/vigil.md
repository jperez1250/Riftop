## 2025-05-18 - Integration Test Lint Suppressions & Clippy Parity
**Challenge:** Adding automated integration and unit test coverage in Riftop caused `cargo clippy --all-targets -- -D warnings` failures due to default `#![deny(clippy::unwrap_used, clippy::expect_used)]` enforced at the crate root and strict Rust 1.94+ lints (`clippy::manual_repeat_n`).
**Strategy:** Standardized top-level `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::manual_repeat_n)]` in integration test files under `tests/` and `#[allow(clippy::unwrap_used, clippy::expect_used)]` on unit test modules within `src/`.
**Prevention:** Always include Clippy allow attributes on test modules/files so test assertion helpers and packet generation loops compile cleanly under strict CI linting.
