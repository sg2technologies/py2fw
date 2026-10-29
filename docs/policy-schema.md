# Policy Schema

```yaml
version: 1
objects:
  name:
    - 10.0.0.1
    - 10.0.0.0/24
    - host.example.com
groups:
  group_name:
    - name
services:
  https:
    protocol: tcp
    port: 443
policies:
  - name: rule_name
    source: [group_name]
    destination: [name]
    service: [https]
    action: allow
    enabled: true
    description: Optional audit note.
exceptions:            # optional; see guardrails.md
  - rule: rule_name
    finding: Open SSH
    reason: Why this risk is accepted.
    ticket: SEC-42
    expires: 2026-12-31
```

## Fields

- **Actions:** `allow`, `deny`, `reject`.
- **Protocols:** `tcp`, `udp`, `icmp`, `any`.
- **Ports:** an integer (`443`), a numeric string (`"443"`), a range string
  (`"1000-2000"`), or a list of integers (`[80, 443]`). Ranges are preserved as
  ranges through the whole pipeline — they are never expanded into per-port rules.
- `icmp` and `any` services must **not** carry a `port`.
- `any` as an object value (or the aliases `0.0.0.0/0`, `::/0`) means "any address".
- **Duplicate keys** anywhere in the file are rejected, with both line numbers.
- **Exceptions** need `rule`, `finding`, a non-blank `reason` and an `expires`
  date. The rule must exist. `critical` findings cannot be waived.

## Evaluation semantics

Rules are evaluated top-to-bottom, first match wins. If no rule matches, the
implicit default is **deny**. `py2fw simulate` and `py2fw explain` expose this
decision for a specific `(source, destination, protocol, port)` flow.
