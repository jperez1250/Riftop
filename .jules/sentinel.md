# Sentinel Security Journal

## 2025-10-04 - Unsanitized Reverse DNS PTR Responses
**Vulnerability:** Unsanitized PTR hostnames returned from reverse DNS lookups stored directly in `DnsCache` could contain ASCII control characters (such as ANSI escape codes) or arbitrary unbounded string lengths. Rendering these in TUI/terminal output leads to terminal escape sequence injection and potential UI corruption or denial-of-service via memory exhaustion.
**Learning:** Reverse DNS responses are untrusted external input. When `DnsCache::insert` stored `Option<String>` directly, untrusted hostnames propagated directly into TUI rendering logic and text exporters.
**Prevention:** Always sanitize string data received from external network lookups by stripping control characters (`!c.is_control()`) and truncating to protocol specification maximums (253 characters for RFC 1035 hostnames) at insertion time into cache structures.
