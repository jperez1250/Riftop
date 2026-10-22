# Bolt's Performance Journal - Critical Learnings

## 2026-03-29 - Eliminate Heap Allocations for `IpAddr` Display in JSON Export
**Learning:** `write_json` in `src/export.rs` was formatting `s.key.a` and `s.key.b` by calling `.to_string()` and passing the string to `json_escape()`. Standard `IpAddr` string representations consist exclusively of ASCII digits, dots, colons, and hex characters, which never contain JSON control characters, quotes, or backslashes. Wrapping them in `json_escape(&ip.to_string())` resulted in 4 redundant heap allocations per flow snapshot entry.
**Action:** Format `IpAddr` values directly into the output stream using `write!(out, "...", s.key.a, s.key.b)` to eliminate intermediate `String` heap allocations completely during JSON snapshot export.
