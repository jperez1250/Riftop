# Sentinel's Journal

## 2026-03-30 - Sanitize untrusted hostnames from DNS resolution
**Vulnerability:** Untrusted hostnames returned from reverse DNS PTR resolution could contain control characters (e.g. terminal escape sequences, raw newlines, null bytes) or excessively long strings leading to UI formatting issues, log injection, or memory bloat.
**Learning:** `dns_lookup::lookup_addr` returns arbitrary string values from DNS responses without filtering control characters or enforcing domain name length limits.
**Prevention:** Always sanitize untrusted external strings before inserting them into state/cache by stripping `c.is_control()`, trimming whitespace, and truncating to RFC 1035 max hostname length (253 bytes) while preserving UTF-8 character boundaries.
