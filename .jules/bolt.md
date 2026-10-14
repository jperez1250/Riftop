# Bolt's Journal - Critical Performance Learnings

## 2025-05-18 - Eliminating Hot Path Entry Clones & Vector Allocations in Flow Processing
**Learning:** `FlowKey` consists of primitive types (`IpAddr`, `u16`, `u8`), making it eligible for `Copy`. Deriving `Copy` and utilizing `HashMap::entry(key).or_insert_with_key(...)` prevents key copies or clones on existing map lookups during packet ingestion. Furthermore, using `list.truncate(n)` instead of `.take(n).collect()` in top flow sorting avoids creating an intermediate heap `Vec`.
**Action:** Always check if small key structs can derive `Copy` and prefer in-place vector modifications over iterator `.collect()` calls in performance-sensitive query paths.
