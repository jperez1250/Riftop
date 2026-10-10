## 2025-05-18 - Reverse DNS Hostname Control Character and Buffer Bounding

**Vulnerability:** Untrusted reverse DNS PTR lookup results inserted into `DnsCache` contained no input sanitization, allowing arbitrary control characters (including ANSI terminal escape sequences and newlines) and unbounded hostname lengths.
**Learning:** Untrusted network input returned from external systems (such as reverse DNS PTR responses) can be abused for terminal escape injection in TUI apps and resource exhaustion if not sanitized prior to storing in in-memory caches or rendering in views.
**Prevention:** Always sanitize untrusted external strings by stripping control characters (`c.is_control()`) and truncating to protocol-defined limits (e.g. 253 bytes for RFC 1035 hostnames) respecting UTF-8 character boundaries (`is_char_boundary`).
