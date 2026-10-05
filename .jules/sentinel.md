# Sentinel Journal - Critical Security Learnings

## 2025-05-18 - Untrusted DNS PTR Response Control Character Injection
**Vulnerability:** Reverse DNS responses (PTR lookups) inserted into `DnsCache` were unvalidated, allowing untrusted or spoofed hostnames with control characters (e.g. ANSI escape sequences, line breaks) or excessive lengths to be stored and rendered in TUI/terminal output and exports.
**Learning:** `dns_lookup::lookup_addr` returns arbitrary string data from external DNS PTR answers. Inserting these strings directly into cache buffers exposes terminal interfaces to ANSI injection/manipulation and logs/exports to format corruption.
**Prevention:** Always sanitize external string inputs (such as DNS PTR records) by filtering `!c.is_control()`, trimming whitespace, and capping string lengths to standard limits (RFC 1035 max 253 chars) prior to storage or rendering.
