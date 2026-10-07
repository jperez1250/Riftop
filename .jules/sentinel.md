# Sentinel Security Journal

## 2025-10-07 - Reverse DNS Hostname Sanitization
**Vulnerability:** Untrusted reverse DNS (PTR) lookups could return strings containing ASCII control characters (such as ANSI escape codes `\x1b[...`, newlines, or null bytes) or excessively long strings (> 253 characters). When displayed in the terminal UI (TUI) or logs, unsanitized escape sequences cause Terminal Escape Injection attacks (CWE-150 / CWE-117) and display corruption.
**Learning:** External network inputs and DNS resolution responses must never be directly rendered or cached without control character filtering and length constraints.
**Prevention:** Sanitize resolved hostnames in `DnsCache::insert` by filtering control characters with `!c.is_control()` and truncating length to 253 characters (RFC 1035).
