## 2025-05-20 - Sanitize Untrusted DNS Reverse Lookup Hostnames and Enforce Crate-Level Forbid Unsafe

**Vulnerability:** Reverse DNS PTR lookup results from untrusted network DNS servers were stored directly in `DnsCache` without sanitizing ASCII/Unicode control characters or bounding string length. This exposed TUI rendering and log output to ANSI escape code injection / terminal spoofing and potential unbounded string memory allocation.
**Learning:** Network-ingested string data (like PTR responses) displayed in terminal UIs can carry malicious ANSI sequences or oversized payloads. In Rust, filtering control characters via `!c.is_control()` and truncating to RFC 1035 FQDN limit (253 chars) at cache ingestion point cleanly neutralizes terminal injection.
**Prevention:** Always sanitize untrusted input strings at the point of cache insertion/ingestion before passing them to display or export layers. Enforce `#![forbid(unsafe_code)]` at crate roots `src/lib.rs` and `src/main.rs`.
