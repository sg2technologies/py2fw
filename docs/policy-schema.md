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
```

## Fields

- **Actions:** `allow`, `deny`, `reject`.
- **Protocols:** `tcp`, `udp`, `icmp`, `any`.
- **Ports:** an integer (`443`), a numeric string (`"443"`), a range string
  (`"1000-2000"`), or a list of integers (`[80, 443]`). Ranges are preserved as
  ranges through the whole pipeline — they are never expanded into per-port rules.
- `icmp` and `any` services must **not** carry a `port`.
- `any` as an object value (or the aliases `0.0.0.0/0`, `::/0`) means "any address".

## Evaluation semantics

Rules are evaluated top-to-bottom, first match wins. If no rule matches, the
implicit default is **deny**. `py2fw simulate` and `py2fw explain` expose this
decision for a specific `(source, destination, protocol, port)` flow.
