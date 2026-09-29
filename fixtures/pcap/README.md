# PCAP fixtures

Deterministic packet captures for regression tests. **Do not** rely on live traffic.

## Adding a fixture

1. Capture with tcpdump: `tcpdump -i eth0 -c 100 -w sample.pcap 'ip or ip6'`
2. Or craft minimal frames with scapy / pktgen.
3. Document expected top flows and approximate rates in `tests/regression_*.rs`.
4. Keep files small (< 1 MB preferred).

## Privacy

Strip or anonymize any sensitive addresses before committing.
