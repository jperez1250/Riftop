## 2025-05-18 - Sanitize DNS Hostnames in DnsCache
**Vulnerability:** Untrusted reverse DNS hostname lookups could inject ANSI escape sequences or control characters into TUI/logs, or introduce memory consumption issues with excessively long domain names.
**Learning:** Hostnames returned by standard DNS resolvers are untrusted network data.
**Prevention:** Filter control characters (`!c.is_control()`) and truncate domain names at RFC 1035 boundaries (253 bytes) respecting UTF-8 character boundaries (`is_char_boundary`).
