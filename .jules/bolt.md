## 2025-10-19 - Zero-Copy Entry Insertion in Hot Packet Processing
**Learning:** Calling `key.clone()` when accessing `HashMap::entry(key.clone()).or_insert_with(...)` causes unnecessary key cloning/copying on every single packet processed, even for existing flow entries. Utilizing `or_insert_with_key(|k| ...)` with `Copy` keys completely eliminates copying/cloning when an entry is already present in the map.
**Action:** Prefer `or_insert_with_key` for map insertions in hot loops when the key is already calculated or passed by value.
