## 2025-05-18 - Enforcing `forbid(unsafe_code)` Inner Attribute at Crate Roots
**Vulnerability:** Absence of explicit inner attribute `#![forbid(unsafe_code)]` at crate entrypoints (`src/lib.rs` and `src/main.rs`) relying solely on `Cargo.toml` lint configuration.
**Learning:** `Cargo.toml` `[lints.rust]` rules can be overridden or bypassed in workspace sub-crates or downstream builds depending on compiler flags, whereas `#![forbid(unsafe_code)]` inside entrypoint source files provides an immutable compiler guarantee against `unsafe` code blocks across all build environments.
**Prevention:** Always declare `#![forbid(unsafe_code)]` at top of `lib.rs` and `main.rs` in pure-safe Rust applications.
