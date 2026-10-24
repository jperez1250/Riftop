## 2025-05-18 - DNS PTR Control Character Injection & IPv4 Link-Local Filtering Gap

**Vulnerability:**
1. Reverse DNS lookups (PTR records) inserted untrusted hostnames into `DnsCache` without sanitizing control characters or bounding string length, opening ANSI escape sequence injection vectors in TUI rendering and logs.
2. `PacketFilter::accept` checked IPv6 link-local addresses (`fe80::/10`) when `allow_link_local` was false, but omitted IPv4 link-local addresses (`169.254.0.0/16`), allowing link-local IPv4 traffic to bypass default filtering.

**Learning:**
1. Reverse DNS responses are attacker-controlled input and must be sanitized (control characters stripped with `!c.is_control()`) and bounded (RFC 1035 253-byte max) at valid UTF-8 character boundaries before caching or displaying in terminal UIs.
2. Dual-stack packet filtering rules must symmetrically enforce link-local address checks across both IPv4 (`169.254.0.0/16`) and IPv6 (`fe80::/10`).

**Prevention:**
Always sanitize external text inputs before storing them in shared application caches or displaying them in terminal interfaces, and ensure protocol filters cover both IPv4 and IPv6 families equally.
