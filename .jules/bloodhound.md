## 2026-03-31 - IPv4 Link-Local Filtering Gap & Non-Saturating Instant Arithmetic

**Issue:** `PacketFilter::accept` only checked for IPv6 link-local addresses (`fe80::/10`) when `allow_link_local` was set to `false`, allowing IPv4 link-local addresses (`169.254.0.0/16`) to pass through unhandled. Additionally, `FlowTable::expire` relied on `now.duration_since(s.last_seen)` which risks panicking or producing unexpected behavior if packet timestamps arrive out of order or regress.

**Fix:** Implemented `is_link_local_v4` in `src/filters.rs` and added IPv4 link-local match arms to `PacketFilter::accept`. Updated `FlowTable::expire` to use `now.saturating_duration_since(s.last_seen)`.

**Prevention:** Always cover dual-stack IPv4 and IPv6 variants symmetrically when creating network classification logic, and enforce `saturating_duration_since` across all timestamp comparison paths.
