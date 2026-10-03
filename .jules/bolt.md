# Bolt Journal - Critical Learnings

## 2025-05-18 - HashMap Lookup Optimization in Flow Processing Hot Path
**Learning:** `HashMap::entry(key.clone())` forces a key clone on every packet before lookup. For existing flows (>99% of packets), `self.flows.get_mut(&key)` avoids key cloning entirely.
**Action:** Prefer `get_mut(&key)` for hot path map lookups when keys are owned values, falling back to `entry(key.clone())` or insertion only on key absence (`None`).
