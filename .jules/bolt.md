## 2025-05-18 - In-Place Truncation in FlowTable::top_sorted
**Learning:** `FlowTable::top_sorted` previously performed an unnecessary vector reallocation by consuming the sorted `Vec<&FlowStats>` with `into_iter().take(n).collect()`. Calling `list.truncate(n)` in-place avoids allocating a second `Vec` on every UI refresh, export, or top-flow query.
**Action:** Use in-place `truncate(n)` when slicing or limiting an already allocated, sorted vector instead of re-collecting through an iterator.
