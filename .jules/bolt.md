## 2025-05-18 - Avoid redundant Vec allocations in FlowTable::top_sorted
**Learning:** `list.into_iter().take(n).collect()` allocates a second vector when selecting top elements from a sorted vector slice.
**Action:** Use in-place vector truncation `list.truncate(n)` after sorting to modify the vector in-place without heap reallocation.
