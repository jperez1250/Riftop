# Riftop roadmap

## Fase 1 — Compatibilidad

- [x] libpcap, IPv4/IPv6, flows, 2/10/40s
- [x] BPF, net-filter, link-local
- [x] TUI básica, DNS async, PCAP offline + tests
- [x] Totales globales (CAPTURED vs VISIBLE)
- [x] Agregación host-pair / source / destination
- [x] TUI sobre PCAP (mismo UI que live)
- [ ] Capacidades / drop root (documentado; setcap en README)

## Fase 2 — Modernización

- [x] Snapshot inmutable para TUI
- [x] JSON export (`--output json`)
- [x] CAPTURE vs DISPLAY explícito en header TUI
- [ ] CSV export
- [ ] Config TOML
- [ ] Channel acotado capture → engine
- [ ] Mejora interfaces (VLAN, netns)

## Fase 3 — Troubleshooting

- [ ] TOP hosts/ports/protocols (teclas 1–5)
- [ ] Métricas TCP básicas
- [ ] Alertas por rate

## Fase 4 — Integración

- [ ] Prometheus
- [ ] HTTP API mínima
- [ ] Container/netns labels
