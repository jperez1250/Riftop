# Bolt's Journal - Critical Learnings

## 2026-10-07 - Pass FlowKey by Value to Avoid Allocation
**Learning:** `FlowKey` consists of two `IpAddr` instances, two `u16` ports, and a `u8` protocol, making its size small and copyable. Deriving `Copy` allows passing `key` by value to `HashMap::entry()` in hot loops without needing `.clone()`.
**Action:** Always derive `Copy` on small key types in packet processing hot paths to eliminate `.clone()` overhead when inserting or updating map entries.
