## 2025-05-18 - Avoid heap allocations in string escaping with Cow<'_, str>
**Learning:** Returning `Cow<'_, str>` from string escaping routines (such as `json_escape`) and performing a fast byte scan (`!s.bytes().any(...)`) eliminates heap allocations for strings that require no escaping, while `write!(out, ...)` via `std::fmt::Write` avoids intermediate `format!` allocations for control character formatting.
**Action:** Use `Cow<'_, str>` for string transformation helpers where the common path requires no modifications to borrow input slices directly.
