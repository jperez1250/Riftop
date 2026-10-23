# Bolt's Journal - Critical Performance Learnings

## 2025-02-18 - Zero-Allocation Case-Insensitive String Filter Matching
**Learning:** In UI redrawing loops, calling `to_lowercase()` on strings (`&str` or `Cow<str>`) causes heap allocations every frame for every rendered flow row. Since hostnames (RFC 1035) and IP address strings in Riftop are predominantly ASCII, byte slice window comparison with `window.eq_ignore_ascii_case()` achieves zero-allocation case-insensitive matching without allocating temporary `String` instances.
**Action:** Prefer `eq_ignore_ascii_case` or ASCII window slice checks in string filter hot paths, falling back to `to_lowercase()` allocation only when `is_ascii()` returns false.
