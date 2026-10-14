# Bloodhound's Journal - Critical Learnings Only

## 2025-05-18 - Unsanitized DNS PTR Hostname Display & Injection
**Issue:** Hostnames retrieved from reverse DNS PTR queries (`dns_lookup::lookup_addr`) were stored into `DnsCache` without sanitization or length bounding. Malicious PTR records containing control characters (e.g., ANSI escape sequences `\x1b[2J`, newlines, null bytes) or ultra-long strings (over 253 bytes) could corrupt TUI rendering, text exports, or consume excess memory.
**Fix:** Implemented `sanitize_hostname` in `src/dns/cache.rs` to parse out ANSI escape sequences, strip control characters, and bound hostnames to 253 bytes (RFC 1035 max) at UTF-8 character boundaries during `DnsCache::insert`.
**Prevention:** Always validate and sanitize external strings from network responses (DNS, HTTP headers, PCAP packet payloads) before inserting into shared cache stores or displaying in user interfaces.
