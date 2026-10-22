# Sentinel Security Journal

## 2025-05-18 - Unsanitized Reverse DNS Hostnames (Terminal/Output Injection & RFC 1035 Violations)
**Vulnerability:** Untrusted reverse DNS (PTR) responses could contain ANSI escape sequences, control characters (`\r`, `\n`, `\0`), or arbitrarily long strings.
**Learning:** Displaying unsanitized PTR hostnames in terminal UIs (Ratatui/Crossterm) or text/JSON outputs creates potential terminal control injection / display spoofing vectors and can violate RFC 1035 max domain length (253 bytes).
**Prevention:** Always sanitize untrusted DNS inputs with `!c.is_control()` and enforce length limits at valid UTF-8 character boundaries (`is_char_boundary`) before caching or rendering.
