## 2025-05-18 - Sanitize reverse DNS hostnames in DnsCache
**Vulnerability:** Untrusted reverse DNS PTR record responses from external DNS servers or malicious networks can contain control characters or arbitrary length strings, presenting potential log injection / terminal corruption vectors or unbounded memory allocation risks.
**Learning:** `dns_lookup::lookup_addr` returns unvalidated strings. In Rust, string slicing by byte offsets can panic if an offset falls inside a multi-byte UTF-8 sequence.
**Prevention:** Filter out control characters (`!c.is_control()`) and truncate to RFC 1035 limit (253 bytes) using `is_char_boundary` to guarantee valid UTF-8 slice boundaries without panicking.
