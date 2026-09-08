# Exporters

Exporter plugins isolate vendor-specific syntax from the Py2FW compiler.

| Target | Model | Notes |
|---|---|---|
| `iptables` | prefix, allow/deny/reject | splits IPv4/IPv6 into `*filter` / ip6tables sections |
| `nftables` | prefix, allow/deny/reject | `inet` table, family-aware `ip`/`ip6` matches |
| `ciscoasa` | prefix, allow/deny | `eq` / `range` port syntax |
| `fortigate` | object, allow/deny | emits `config firewall address`, `addrgrp`, `service custom` |
| `paloalto` | object, allow/deny/reset-both | emits `set address` / `set service` object definitions |
| `checkpoint` | object, allow/deny/reject | management-API payload with `objects` + `access_rules` |
| `aws-sg` | prefix, **allow only** | ingress permissions; `deny`/`reject` rules dropped (lossy) |
| `azure-nsg` | prefix, allow/deny | resolved CIDRs, `Tcp`/`Udp` protocol, port ranges |
| `kubernetes` | prefix, **allow only** | `NetworkPolicy` ingress with `port`/`endPort` |

## Rules

- Every exporter consumes `FirewallIR` only. Do not import `py2fw.parser` or
  `py2fw.analyzers` inside an exporter module.
- Declare a `Capabilities` value so `compile` can warn when the target loses
  policy semantics (dropped `deny` rules, downgraded `reject`, unsupported IPv6).
- Object names that resolve to "any" are emitted as the vendor's native
  any/all keyword, not as an undefined object reference.
- Port ranges are emitted with native range syntax, never expanded per-port.

## Golden tests

`tests/golden/<target>.txt` holds the expected output for `examples/basic.yaml`.
Regenerate after an intentional change and review the diff.
