# Compliance Mapping

`py2fw compliance <policy>` maps what Py2FW can observe in a compiled policy to
specific controls in three frameworks:

| Framework | Selector |
|---|---|
| PCI DSS v4.0 | `-f pci` |
| NIST SP 800-53 Rev 5 | `-f nist` |
| CIS Controls v8 | `-f cis` |

Pass `-f` more than once to combine frameworks; the default is all three.
`--json` emits the machine-readable form.

## Statuses

- **pass** — the policy demonstrably supports the control (e.g. no permit-any-any
  rule exists, so PCI 1.4.1 passes).
- **review** — the control depends on information Py2FW does not model: traffic
  direction, security zones, DMZ placement, device-level logging. These need a
  human decision.
- **fail** — the policy actively contradicts the control, and the offending
  rules are named.

`compliance` exits non-zero when any control fails, so it can gate a pipeline.

## What is checked

| Control | Basis |
|---|---|
| PCI 1.2.1 / NIST CM-7 | untrusted source permitted to all ports |
| PCI 1.2.5 | wide port range (≥1024 span) from an untrusted source |
| PCI 1.4.1 / NIST SC-7 / CIS 4.4 | permit-any-to-any allow rule |
| PCI 1.4.4 | database port reachable from an untrusted source |
| NIST SC-7(5) | implicit default-deny (always pass — it is the engine's semantics) |
| NIST AC-4 | every rule names explicit source/destination/service |
| CIS 13.4 | presence of scoped segment-to-segment rules |

"Untrusted source" means `any`, `0.0.0.0/0`, or a public prefix at or below
`/16` (IPv4) / `/48` (IPv6).

These are heuristics, not a certification. Treat `review` as the real work.
