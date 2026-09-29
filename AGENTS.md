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

## 3. Build, Test, and Quality Commands

Always run these commands before submitting changes:

### Build & Check
```bash
cargo check
cargo build
```

### Testing
Run unit and integration tests:
```bash
cargo test
```

To run a specific test target:
```bash
cargo test --test regression_flow
cargo test --test regression_filters
cargo test --test regression_r1_r4
```

### Linting & Formatting
```bash
cargo clippy
cargo fmt --check
```

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

## 5. Coding Conventions & Safety

1. **`unsafe_code = "forbid"`**: Do not introduce `unsafe` blocks.
2. **Imports**: Binary modules (`main.rs`, `cli.rs`, `ui/mod.rs`, `config.rs`, `top.rs`, `alerts.rs`, `interfaces.rs`, `privileges.rs`) should import shared types from the library crate (`riftop::...`).
3. **Ratatui API**: Use Ratatui 0.26 compatible calls (e.g., `f.size()` for `Frame`).
4. **Etherparse API**: Use Etherparse 0.14 compatible calls (e.g., `NetSlice`, `Ipv4Slice::header().source_addr()`).
5. **Unicode Sequences**: Use bracketed syntax in format strings (e.g., `\u{2194}`).
