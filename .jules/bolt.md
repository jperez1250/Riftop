# Bolt's Journal - Critical Performance Learnings

## 2025-03-30 - Partial Selection with `select_nth_unstable_by` in `FlowTable::top_sorted`
**Learning:** Full sorting of large flow collections ($O(N \log N)$) when only top $n$ items ($n \ll N$) are needed incurs heavy comparison overhead, especially when comparing items involves dynamic flow rate calculations (`rate_2s`, `rate_10s`, `rate_40s`).
**Action:** When selecting top $n$ flows from a collection, use `slice::select_nth_unstable_by(n, cmp)` to partition the slice in $O(N)$ expected time, truncate to $n$, and sort only the top $n$ items in $O(n \log n)$ time. This avoids thousands of rate window calculations and eliminates redundant vector allocations.
