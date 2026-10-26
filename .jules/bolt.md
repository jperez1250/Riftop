# Bolt's Journal - Riftop Performance Engineering

## 2025-05-18 - In-place Vector Truncation in `FlowTable::top_sorted`
**Learning:** `list.into_iter().take(n).collect()` creates a secondary heap allocation when building the top N flows list on every frame render or snapshot generation. Using `list.truncate(n)` mutates the vector in-place and avoids allocating a second vector buffer.
**Action:** Always prefer `vec.truncate(n)` over `vec.into_iter().take(n).collect()` when truncating an owned `Vec` after sorting.
