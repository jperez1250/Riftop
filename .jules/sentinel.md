# Sentinel's Security Journal

## 2026-10-02 - Reverse DNS Hostname Sanitization and Bounding in DnsCache
**Vulnerability:** Untrusted PTR records from reverse DNS lookups could contain ASCII control characters (such as terminal escape sequences, carriage returns, or newlines) or arbitrary unbounded lengths. When displayed directly in TUI views (`render.rs`) or serialized to output streams, malicious responses could cause terminal display corruption (ANSI escape injection) or unbounded memory consumption.
**Learning:** External network inputs like reverse DNS names are attacker-controlled. In Rust, standard library string handling does not validate or sanitize domain names for terminal safety, and arbitrary remote DNS responses can exceed standard RFC bounds (RFC 1035 max 253 octets) or split multi-byte UTF-8 sequences if naively sliced.
**Prevention:** Filter out ASCII control characters (`!c.is_ascii_control()`) upon inserting resolved hostnames into `DnsCache`, and bound lengths to 253 bytes ensuring truncation happens on valid UTF-8 character boundaries (`is_char_boundary`).
