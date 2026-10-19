## 2025-05-18 - FlowKey Canonical Endpoint Ordering in Flow Table Exports
**Challenge:** Testing `write_json`, `write_text`, and `write_csv` exports against a populated `FlowTable` resulted in assertion failures when expecting `src` and `dst` fields to match the exact order passed to `FlowTable::record`. `FlowKey::new` canonicalizes endpoints by sorting `(src, sport)` and `(dst, dport)`, which may swap `a` and `b` in the stored `FlowKey`.
**Strategy:** In export tests, construct test flow IP pairs where `ip_a <= ip_b` or explicitly account for canonical ordering of `key.a` and `key.b` when asserting exported field values.
**Prevention:** Always verify canonical `FlowKey` endpoint ordering when writing tests that inspect internal flow key representations or exported string output.
