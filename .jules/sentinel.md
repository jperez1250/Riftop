# Sentinel Security Journal

## 2025-05-18 - Unsanitized Reverse DNS PTR Hostnames in DnsCache
**Vulnerability:** Reverse DNS PTR lookup responses are untrusted network data. Hostnames inserted into `DnsCache` without sanitization could contain ANSI control characters (leading to terminal corruption or escape injection in TUI rendering) or excessive length payloads (leading to UI layout breakage or memory overhead).
**Learning:** When ingesting strings from external network lookups or system calls in Rust UI applications, raw strings should never be rendered directly without defensive filtering of control characters and length bounding.
**Prevention:** Always sanitize network-sourced strings (such as PTR domain names) by stripping control characters (`!c.is_control()`) and truncating to RFC 1035 limits (253 bytes) respecting UTF-8 character boundaries before storing them in cache or displaying them in the user interface.
