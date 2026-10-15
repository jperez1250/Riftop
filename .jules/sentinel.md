## 2025-05-18 - Sanitize Reverse DNS Hostnames Against Terminal Injection and Memory Bloat
**Vulnerability:** Untrusted reverse DNS PTR responses returned by `dns_lookup::lookup_addr` were cached raw in `DnsCache` without sanitization. Malicious or spoofed PTR records containing control characters/ANSI escape sequences could corrupt TUI terminal rendering or cause buffer bloat with oversized hostnames.
**Learning:** External network inputs (like PTR records) must be treated as untrusted strings before caching or displaying in CLI/TUI outputs. Standard RFC 1035 limits domain names to 253 bytes.
**Prevention:** Always strip control characters (`c.is_control()`) and enforce UTF-8-safe length bounds (e.g., 253 bytes max) when storing/rendering hostnames from DNS responses.
