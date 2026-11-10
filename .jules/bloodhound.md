## 2026-11-10 - IPv4 Link-Local Filter Bypass in PacketFilter
**Issue:** `PacketFilter::accept` failed to filter IPv4 link-local addresses (169.254.0.0/16, RFC 3927) when `allow_link_local` was set to false, only checking IPv6 link-local addresses (fe80::/10). This allowed IPv4 link-local autoconfiguration packets to bypass the default filter.
**Fix:** Introduced `is_link_local_v4` checking the 169.254.0.0/16 prefix and added guard patterns for both source and destination IPv4 addresses in `PacketFilter::accept`.
**Prevention:** Always pair dual-stack IPv4/IPv6 packet filtering invariants in regression test suites, verifying both address families when features specify protocol-agnostic behaviors like link-local filtering.
