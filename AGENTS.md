# AGENTS.md — Riftop Developer & Agent Guide

## Purpose

`Riftop` is a Rust-based real-time network bandwidth monitor and an ongoing modernization of the original C `iftop` codebase.
This file contains mandatory instructions, environment setup procedures, build/test commands, and architectural rules for autonomous coding agents, including Jules.

---

# 1. ENVIRONMENT SETUP & SNAPSHOT PREPARATION

Google/Jules automatically inspects `AGENTS.md` in the root directory to set up the development environment, generate execution plans, and complete tasks.

## Environment Initialization

Execute the repository environment setup script before running tasks or creating environment snapshots:

```bash
bash scripts/setup-environment.sh
```

### Dependencies & Linker Configuration
`Riftop` depends on `libpcap`. In container and sandbox environments, `libpcap.so` must be present in search paths:

```bash
export LIBRARY_PATH="/app/target/lib:/usr/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}"
ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so 2>/dev/null || true
```

---

# 2. MANDATORY VERIFICATION LOOP

Before marking any plan step complete or submitting code, execute this verification loop locally:

```bash
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo fmt --all -- --check
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo check --all-targets --all-features
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo test --all-targets --all-features
LIBRARY_PATH=/app/target/lib:/usr/lib/x86_64-linux-gnu cargo clippy --all-targets --all-features -- -D warnings
```

---

# 3. NON-DESTRUCTIVE DEVELOPMENT POLICY

## Absolute Rule
- Do NOT delete working code merely because it appears old, redundant, or unused.
- Do NOT perform opportunistic or stylistic refactoring.
- Do NOT replace an entire module or file when a targeted edit is sufficient.
- Do NOT remove a function, struct, test, fixture, or compatibility layer unless explicitly required.

---

# 4. NO REGRESSIONS & TEST INTEGRITY

Every bug fix must preserve previously working behavior.

Mandatory workflow:
1. Reproduce the defect.
2. Add or improve a regression test.
3. Confirm the test fails on the original bug.
4. Apply the smallest correct implementation fix.
5. Run the regression test and the complete test suite.
6. Verify the final diff.

Never weaken an assertion merely to make a test pass. Never replace exact assertions with generic checks (`is_some()`, `is_finite()`, `> 0`).

---

# 5. RIFTOP SEMANTIC INVARIANTS

1. **Flow Identity (`FlowKey`) vs Presentation (`show_ports`)**
   - Changing UI presentation settings (`--ports`, `--no-ports`) MUST NOT alter the underlying `FlowKey` protocol identity or collapse distinct protocols.

2. **Endpoint Accounting (`bytes_a_to_b`, `bytes_b_to_a`)**
   - Endpoint ordering (`a <= b`) must preserve exact directional byte counters. Top Hosts and Top Ports MUST use `bytes_a_to_b` and `bytes_b_to_a` to prevent traffic double-counting.

3. **Direction Classification**
   - Local interface traffic is classified as `Direction::Sent` or `Direction::Received`. Offline PCAPs without local interface context MUST use `Direction::Unknown` rather than inventing local host identity.

4. **Capacity Limits (`MAX_FLOWS = 100,000`)**
   - Centralize flow entry admission in `FlowTable`. Traffic rejected due to capacity MUST NOT be recorded in accepted flow statistics.

5. **Rate Windows**
   - `RateWindow::rate` computes byte rates over exact `max_age` durations (`total / max_age.as_secs_f64()`).

6. **PCAP Replay Clock**
   - Offline PCAP timestamp calculations MUST use deterministic relative time (`pcap_start`, `pcap_end`, `replay_now`).

7. **DNS Concurrency & Negative Caching**
   - `DnsCache` uses a bounded worker thread pool (4 workers) and explicit `DnsState` (`Resolving`, `Resolved`, `Negative`) with pending request recovery.

8. **Configuration & CLI Precedence**
   - Precedence order: Explicit CLI (`Option<T>`) > Configuration File (`$HOME/.config/riftop/config.toml`) > Built-in Defaults.
   - Automatic current working directory `./riftop.toml` loading is disabled for safety.

---

# 6. STOP CONDITIONS

Stop and request clarification if:
- Requested changes conflict with documented domain invariants.
- A fix requires large-scale code removal.
- Tests contradict documentation or specifications.

---

# 7. FINAL REPORT DELIVERABLES

Every completed task must provide:
1. Root cause description
2. Applied fix summary
3. Regression test evidence
4. List of changed files
5. Actual command execution results
6. Remaining risks, if any
