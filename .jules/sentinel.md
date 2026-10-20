# Sentinel Security Journal

## 2025-03-08 - DNS PTR Response Control Character and Length Sanitization
**Vulnerability:** Untrusted reverse DNS PTR resolution results inserted directly into `DnsCache` could contain ANSI escape sequences/control characters or exceed RFC 1035 hostname limits (253 bytes). When rendered in TUI or plain text outputs, embedded control characters (such as `\x1b[2J`) cause terminal display corruption (ANSI code injection) or UI layout breakage.
**Learning:** External network input from reverse DNS lookups must be sanitized before being stored in shared application caches or passed down to UI render functions. Slicing long strings to limit length in Rust must verify UTF-8 character boundaries using `is_char_boundary()` to prevent runtime slicing panics.
**Prevention:** Sanitize untrusted hostnames at ingestion in `DnsCache::insert` by filtering control characters (`!c.is_control()`) and truncating to <= 253 bytes at valid UTF-8 boundaries.
