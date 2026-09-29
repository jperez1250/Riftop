# Riftop roadmap

## Fase 1 — Compatibilidad

- [x] libpcap, IPv4/IPv6, flows, 2/10/40s
- [x] BPF, net-filter, link-local
- [x] TUI básica, DNS async, PCAP offline + tests
- [x] Totales globales (CAPTURED vs VISIBLE)
- [x] Agregación host-pair / source / destination
- [x] TUI sobre PCAP (mismo UI que live)
- [x] Privileges: setcap guidance + root warning (`privileges.rs`)

## Fase 2 — Modernización

- [x] Snapshot inmutable para TUI
- [x] JSON / text / CSV export (`--output`)
- [x] CAPTURE vs DISPLAY explícito en header TUI
- [x] Channel acotado capture → engine (`engine.rs`, backpressure + DROP counter)
- [ ] Config TOML
- [ ] Mejora interfaces (VLAN, netns)

## Fase 3 — Troubleshooting

- [x] TOP hosts / ports / protocols (teclas 1–4 / Tab)
- [ ] Métricas TCP básicas
- [ ] Alertas por rate

## Fase 4 — Integración

- [ ] Prometheus
- [ ] HTTP API mínima
- [ ] Container/netns labels

## Privilegios (Linux)

```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin=eip target/release/riftop
./target/release/riftop -i eth0
```
