## 2026-10-02 - Eliminate redundant Vec allocation in FlowTable::top_sorted
**Learning:** `FlowTable::top_sorted` previously performed `list.into_iter().take(n).collect()`, allocating a second `Vec` on every top flows or snapshot rendering query.
**Action:** Use `list.truncate(n)` in-place vector truncation after sorting to retain top items without allocating a new vector buffer.
