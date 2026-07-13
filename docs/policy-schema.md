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

Actions: `allow`, `deny`, `reject`.

Protocols: `tcp`, `udp`, `icmp`, `any`.

Ports may be an integer, a numeric string, or a range string such as `1000-2000`.
