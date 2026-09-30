# AGENTS.md — Riftop Developer & Agent Guide

This document provides instructions, coding conventions, build/test commands, and architectural information for agents and developers working on `riftop`.

---

## 1. Project Overview

`riftop` is a modern real-time bandwidth monitoring command-line tool written in Rust, inspired by the legacy C tool `iftop`.
It captures network packets using `pcap`, decodes IP and transport layers (`etherparse`), aggregates flow statistics, and renders a TUI (`ratatui` + `crossterm`) or exports data (JSON, CSV, text).

---

## 2. Environment Setup & Linker Notes

`riftop` depends on `libpcap`. In sandbox/container environments, ensure `libpcap.so` is available in system/library search paths.

If linking fails due to `-lpcap`, ensure a symlink exists:
```bash
ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so 2>/dev/null || true
```

---

## 3. Mandatory Verification Loop (Compile-Test-Fix)

Before marking any task as complete or opening a PR, you MUST execute this loop locally:

1. **Format Check:** Run `cargo fmt --check`.
2. **Compile Check:** Run `cargo check --all-targets`.
3. **Lint Check:** Run `cargo clippy --all-targets -- -D warnings`.
4. **Prohibit `.unwrap()` / `.expect()`:** Ensure no `.unwrap()` or `.expect()` calls exist in production code (`src/` excluding tests).
5. **Test Suite:** Run `cargo test --all-targets`.

### Failure Handling
If ANY command above fails:
- Read the compiler/linter error output carefully.
- Apply a targeted fix to address the specific error message.
- Re-run the verification loop from Step 1.
- DO NOT submit code if any test or lint check fails.

---

## 4. Architecture & Module Structure

The project is split into a library crate (`riftop` library) and a binary executable (`riftop` binary):

- `src/lib.rs`: Library crate root (`capture`, `dns`, `engine`, `error`, `export`, `filters`, `flow`, `protocols`, `services`).
- `src/main.rs`: CLI binary entrypoint.
- `src/flow/mod.rs`: `FlowTable`, `FlowStats`, `FlowKey`, `RateWindow`, and bandwidth accounting.
- `src/protocols/mod.rs`: Frame and packet decoding (`etherparse` integration).
- `src/capture/mod.rs` & `src/engine.rs`: Live device capture, PCAP file decoding, packet event channels.
- `src/ui/mod.rs`: Ratatui TUI drawing logic.
- `src/config.rs` & `src/cli.rs`: Options parsing and configuration file handling.
- `tests/`: Regression test suite (`regression_flow.rs`, `regression_filters.rs`, `regression_r1_r4.rs`).

---

## 5. Coding Conventions & Safety Rules

1. **`unsafe_code = "forbid"`**: Do not introduce `unsafe` blocks anywhere in the project.
2. **No Unhandled Panics**: Do NOT use `.unwrap()` or `.expect()` in non-test production code in `src/`.
3. **Module Imports**: Binary modules (`main.rs`, `cli.rs`, `ui/mod.rs`, `config.rs`, `top.rs`, `alerts.rs`, `interfaces.rs`, `privileges.rs`) must import shared types from the library crate (`riftop::...`).
4. **Ratatui API**: Use Ratatui 0.26 compatible calls (e.g., `f.size()` for `Frame`).
5. **Etherparse API**: Use Etherparse 0.14 compatible calls (e.g., `NetSlice`, `Ipv4Slice::header().source_addr()`).
6. **Unicode Sequences**: Use bracketed syntax in format strings (e.g., `\u{2194}`).
