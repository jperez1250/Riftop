# Bolt's Journal - Riftop Performance

## 2026-10-02 - Flow Table Recording & Sorting Optimizations
**Learning:** In high-throughput packet processing loops, checking table capacity before contains_key avoids expensive hash calculations on packets under capacity limit, and using `or_insert_with_key` eliminates unconditional key cloning on existing flows. In-place vector truncation (`truncate(n)`) eliminates redundant allocation of new `Vec` instances when sorting top flows.
**Action:** Short-circuit capacity bounds checks before hash lookups and prefer moving keys into entry APIs with `or_insert_with_key`.
