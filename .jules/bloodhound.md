# Bloodhound Journal - Critical Learnings

## 2025-05-18 - Missing IPv4 Link-Local Filtering in PacketFilter
**Issue:** `PacketFilter::accept` checked `is_link_local_v6` when `allow_link_local` was false, but completely omitted IPv4 link-local filtering (`169.254.0.0/16`), allowing link-local IPv4 traffic to bypass default packet exclusion rules.
**Fix:** Implemented `is_link_local_v4` in `src/filters.rs` to detect octets matching `169.254.x.x` and updated `PacketFilter::accept` to drop both IPv4 and IPv6 link-local addresses when `allow_link_local` is false.
**Prevention:** Include dual-stack (IPv4 and IPv6) test cases in filter unit and integration tests whenever protocol address classification logic is modified.
