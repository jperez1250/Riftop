# AGENTS.md — Riftop

## Purpose

Riftop is a Rust-based network bandwidth monitor and an ongoing modernization of the original iftop codebase.

The repository contains working functionality that must be preserved.

Your job is to make the smallest correct change necessary to solve the requested problem while preserving all unrelated behavior.

This file contains mandatory repository rules for autonomous coding agents, including Jules.

---

# 1. NON-DESTRUCTIVE DEVELOPMENT POLICY

## Absolute rule

Do NOT delete working code merely because it appears old, redundant, unused, duplicated, or less elegant.

Do NOT rewrite healthy code simply to make the implementation look cleaner.

Do NOT perform opportunistic refactoring.

Do NOT replace an entire module/file when a targeted change is sufficient.

Do NOT remove a function, structure, module, test, fixture, or compatibility layer unless the task explicitly requires its removal OR there is concrete evidence that the code is unreachable/dead and its removal is proven safe.

Preserving existing behavior has priority over stylistic improvement.

---

# 2. NO REGRESSIONS

Every bug fix must preserve previously working behavior.

Mandatory workflow:

1. Reproduce the problem.
2. Add or improve a regression test.
3. Confirm the test fails for the original bug.
4. Make the smallest implementation change.
5. Run the regression test.
6. Run all relevant existing tests.
7. Run the complete test suite.
8. Review the final diff for unintended changes.
9. Re-check behavior unrelated to the bug.

Never remove an existing test merely because it fails after your change.

Never weaken an assertion merely to make a test pass.

Never replace an exact assertion with a weaker assertion such as:

```rust
assert!(value.is_some());
assert!(value.is_finite());
assert!(value > 0);
```

when the expected value can be known precisely.

---

# 3. CHANGE SCOPE

For each task define:

* files expected to change
* functions expected to change
* behavior that must remain unchanged
* tests that prove the fix

Do not modify unrelated files.

Do not perform broad formatting-only changes.

Do not reorder unrelated code.

Do not rename public APIs unless explicitly required.

Do not change public behavior without a regression test documenting the intended new behavior.

---

# 4. FILE DELETION POLICY

Deleting files is prohibited by default.

A file may only be deleted when:

1. The task explicitly requires it, OR
2. The file is provably obsolete,
3. Its replacement already exists,
4. All references to it have been audited,
5. Existing tests covering its behavior remain valid,
6. The deletion is documented in the final summary.

Before deleting a file, report:

```text
File:
Reason:
Replacement:
References checked:
Tests proving safety:
```

Never delete a file simply because it is old, small, duplicated, or apparently unused.

---

# 5. FUNCTION / CODE DELETION POLICY

Do not remove functions or blocks of code solely because the compiler or linter reports them as unused.

First determine:

* Is the function part of a public API?
* Is it used through another module?
* Is it required by integration tests?
* Is it part of compatibility behavior?
* Is it intended for future feature work?
* Is it referenced through macros, trait implementations, dynamic dispatch, reflection, or build-time generation?

Only remove confirmed dead code when the task explicitly permits cleanup.

---

# 6. NEVER REPLACE A WHOLE FILE FOR A SMALL BUG

Prefer targeted edits.

Bad:

```text
rewrite src/flow/mod.rs
```

Good:

```text
modify RateWindow::rate()
add regression test
preserve all unrelated FlowTable behavior
```

Whole-file replacement requires explicit justification.

---

# 7. BASELINE BEFORE CHANGES

Before modifying anything:

```bash
git status --short
git branch --show-current
git log -n 10 --oneline
```

Then run the relevant baseline tests.

Record failures that already existed before the task.

Do not attribute pre-existing failures to your change.

---

# 8. PLAN BEFORE CODE

Before modifying code, inspect:

```text
README.md
AGENTS.md
Cargo.toml
relevant source modules
relevant tests
CI configuration
```

Build a plan containing:

1. root cause
2. expected behavior
3. files to change
4. tests to add/change
5. validation commands
6. risks

Do not start with implementation before understanding the existing architecture.

---

# 9. TEST-FIRST BUG FIXING

For a correctness bug:

```text
existing behavior
      ↓
reproduce
      ↓
failing regression test
      ↓
minimal fix
      ↓
regression test passes
      ↓
full suite passes
```

Do not fix the bug first and invent a test afterwards.

---

# 10. PRESERVE EXISTING TESTS

Tests are part of the product.

Never:

* delete a failing test to make CI green
* reduce test coverage
* remove an edge case because it is inconvenient
* replace exact assertions with weak assertions
* mark tests ignored without explicit justification

When an existing test conflicts with the intended design, document the conflict and update both implementation and test deliberately.

---

# 11. RIFTOP SEMANTIC INVARIANTS

The following are core product behavior and must not be changed accidentally.

## Flow identity

Flow identity must not depend on UI presentation settings.

Changing:

```text
--ports
--no-ports
```

must not corrupt:

```text
protocol identity
endpoint identity
direction
byte counters
packet counters
```

---

## Endpoint accounting

For:

```text
A -> B = X bytes
B -> A = Y bytes
```

the implementation must preserve:

```text
A-to-B = X
B-to-A = Y
total = X + Y
```

regardless of endpoint canonicalization.

---

## Direction

Do not invent direction.

If local-host identity cannot be determined, represent that explicitly.

Offline PCAP must not automatically classify every packet as received.

---

## Rate windows

2s, 10s and 40s rates must have deterministic semantics.

Rate calculations require exact regression tests.

Do not replace exact rate tests with merely:

```text
finite
positive
non-zero
```

---

## Flow limits

MAX_FLOWS must be enforced consistently.

A packet rejected because of capacity must not be reported as successfully stored.

Global counters must have explicit semantics.

---

## PCAP

PCAP timestamp semantics must remain deterministic.

The same PCAP processed twice with the same configuration should produce equivalent statistics.

---

## Filtering

BPF, network filters and screen filters have different semantics.

Do not mix them.

BPF errors must not be silently ignored.

---

## DNS

DNS resolution must not create unbounded resource consumption.

Do not create one unbounded OS thread per unique IP.

---

# 12. ARCHITECTURE BEFORE REFACTORING

Riftop should conceptually follow:

```text
Capture
   ↓
Decode
   ↓
PacketEvent
   ↓
Capture/BPF Filter
   ↓
Network Filter
   ↓
Direction Classification
   ↓
Flow Engine
   ↓
FlowTable
   ↓
Snapshot
   ↓
Top Views / Export / UI
```

Do not collapse these responsibilities merely to reduce code.

Do not move logic across layers without a concrete reason.

---

# 13. ERROR HANDLING

Never silently ignore important errors.

Avoid:

```rust
let _ = operation();
```

when failure affects correctness.

Prefer:

```rust
operation()?;
```

or explicit error handling.

Configuration errors must be visible.

PCAP/BPF errors must be visible.

Resource exhaustion must be observable.

---

# 14. CLIPPY / RUST QUALITY

Do not silence warnings just to obtain a clean build.

Do not add:

```rust
#[allow(...)]
```

unless there is an explicit documented reason.

Do not use:

```rust
unwrap()
expect()
panic!()
```

in production paths unless explicitly justified and allowed by the repository's rules.

---

# 15. REGRESSION TEST MATRIX

Bug fixes should test at least:

```text
normal case
boundary case
empty case
malformed input
previously failing case
reverse direction
IPv4
IPv6
PCAP where applicable
live path where applicable
```

For concurrency changes also test:

```text
duplicate work
resource bounds
shutdown
failure
contention
```

---

# 16. VALIDATION

Run:

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
cargo test --release --all-targets --all-features
cargo test --doc
```

Also run the repository regression script when available:

```bash
./scripts/test-regression.sh
```

If a command cannot be executed, report why.

Never claim a test passed if it was not executed.

---

# 17. FINAL DIFF AUDIT

Before finishing:

```bash
git status --short
git diff --stat
git diff --check
git diff
```

Review every changed file.

Explicitly check:

```text
Did I delete code?
Did I delete tests?
Did I change public behavior?
Did I modify unrelated files?
Did I weaken an assertion?
Did I change semantics while refactoring?
Did I alter CLI behavior?
Did I alter output format?
Did I alter packet accounting?
```

If any answer is yes, justify it in the final report.

---

# 18. FINAL REPORT

Every task must finish with:

## Root cause

What was actually wrong?

## Fix

What changed?

## Regression test

Which test prevents the bug from returning?

## Files changed

List them.

## Files deleted

If none:

```text
None
```

If any exist, explain each deletion.

## Validation

Provide actual command results.

## Remaining risks

List anything not fully verified.

---

# 19. STOP CONDITIONS

Stop and request clarification instead of making speculative destructive changes when:

* the requested behavior conflicts with existing documented behavior
* a fix requires removing a large amount of code
* the existing architecture is unclear
* multiple unrelated designs could solve the issue
* tests contradict the documentation
* the requested change risks breaking compatibility

Do not guess.

Do not "clean up" the repository to compensate for ambiguity.

---

# 20. GOLDEN RULE

The preferred patch is:

```text
small
targeted
tested
reversible
reviewable
```

not:

```text
large
clever
architecturally ambitious
```

Preserve healthy code.

Fix the actual bug.

Prove the fix with a regression test.

Do not create new behavior accidentally.
