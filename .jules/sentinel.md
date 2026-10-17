# Sentinel Security Journal

## 2025-05-18 - Reverse DNS Hostname Sanitization and Bound Checking
**Vulnerability:** Untrusted reverse DNS lookup results from `dns_lookup::lookup_addr` were stored raw in `DnsCache` without sanitization, allowing malicious PTR responses containing ANSI control sequences (terminal injection) or excessive byte length (memory bloat).
**Learning:** External network inputs rendered in terminal UI (Ratatui/Crossterm) or text exports can alter terminal state or cause display corruption if control characters are not explicitly stripped. String truncation must respect UTF-8 character boundaries (`is_char_boundary`).
**Prevention:** Always sanitize untrusted text inputs by filtering control characters (`c.is_control()`) and enforcing domain length limits (RFC 1035 max 253 bytes) before storing or rendering them.
