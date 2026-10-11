## 2025-02-23 - Hostname Sanitization and Bounds Bounding in Reverse DNS Caching
**Vulnerability:** Untrusted hostnames returned from reverse DNS lookups could contain control characters or arbitrary lengths, potentially causing UI corruption, log injection, or memory overhead.
**Learning:** Hostnames parsed from external sources must be sanitized to strip control characters (`char::is_control`) and bounded to 253 bytes per RFC 1035 while preserving UTF-8 character boundaries (`is_char_boundary`).
**Prevention:** Always validate and sanitize untrusted string responses before storing them into application state or rendering them in output/UI.
