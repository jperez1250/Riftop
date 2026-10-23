# Vigil's Testing Journal

## 2026-03-30 - Unit Testing Unwrapped Results and Clippy Strictness in Safe Crate Roots
**Challenge:** Modules in `src/` enforce `#![deny(clippy::unwrap_used, clippy::expect_used)]` crate-wide. Adding unit tests using `unwrap()` inside `#[cfg(test)] mod tests` triggers clippy compilation failures during `cargo clippy --all-targets -- -D warnings`.
**Strategy:** Explicitly annotate test modules with `#[allow(clippy::unwrap_used, clippy::expect_used)]` at the `mod tests` declaration level inside `src/` files, or use matching `Result` assertions.
**Prevention:** Always include `#[allow(clippy::unwrap_used, clippy::expect_used)]` on embedded test modules in `src/` so that tests remain concise without breaking strict clippy linting rules.
