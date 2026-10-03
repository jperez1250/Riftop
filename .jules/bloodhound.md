# Bloodhound's Journal

## 2025-05-18 - Unsanitized PTR Hostnames in DNS Cache
**Issue:** Reverse DNS lookups resolved hostnames from external PTR records without sanitizing control characters or bounding length. Raw PTR hostnames containing ASCII/Unicode control characters (`\n`, `\r`, `\t`, ANSI escape sequences, null bytes) or exceeding RFC 1035 limits (253 chars) were inserted into `DnsCache` as `DnsState::Resolved`, risking terminal UI corruption, output injection, and display overflow.
**Fix:** Added `sanitize_hostname` in `src/dns/cache.rs` that strips control characters (`!c.is_control()`), truncates strings to max 253 characters at UTF-8 char boundaries, and converts hostnames consisting solely of control characters to `DnsState::Negative`.
**Prevention:** Always sanitize external/network-provided strings (DNS PTRs, HTTP headers, packet payload strings) before caching or rendering in TUI/exporters. Verify sanitization logic with dedicated unit tests covering edge cases (control character sequences, empty strings, multi-byte UTF-8 char boundaries).
