# Py2FW

Py2FW is a vendor-neutral firewall Policy-as-Code compiler. Security teams define
policy once in YAML, then **validate → analyze → simulate → diff → compile** it
into vendor configurations — verifying intent before anything reaches a device.

```bash
py2fw validate   examples/basic.yaml
py2fw analyze    examples/basic.yaml
py2fw compliance examples/basic.yaml            # PCI DSS / NIST 800-53 / CIS
py2fw simulate   examples/basic.yaml --src 10.10.1.10 --dst 10.10.2.10 --port 3306
py2fw explain    examples/basic.yaml --src 10.10.1.10 --dst 10.10.2.10 --port 3306
py2fw diff       examples/basic.yaml examples/basic-v2.yaml
py2fw compile    examples/basic.yaml --target fortigate
py2fw targets
py2fw graph      examples/basic.yaml --output policy.svg
```

`validate` and `analyze` report the **source line** of every issue.
Hostnames in objects are passed through literally with a warning; run
`compile --resolve-hosts` to resolve them once via DNS and pin the result in a
`<policy>.py2fw-lock.json` file for reproducible builds.

## Architecture

```text
YAML -> Parser -> Validator -> IR Builder -> Optimizer -> Exporter Plugin -> Vendor Config
                                   |
                                   +-> Evaluation Engine -> simulate / explain / diff
                                   +-> Analyzers          -> analyze
```

Vendor logic lives only in exporter plugins. Parser, validator, resolver,
analyzers, optimizer and the evaluation engine operate exclusively on
vendor-neutral policy data and the `FirewallIR`.

## Policy Example

```yaml
version: 1
objects:
  web: [10.10.1.10]
  db:  [10.10.2.10]
services:
  mysql: { protocol: tcp, port: 3306 }
policies:
  - name: web_to_db
    source: [web]
    destination: [db]
    service: [mysql]
    action: allow
```

## Targets

`iptables`, `nftables`, `fortigate`, `paloalto`, `ciscoasa`, `checkpoint`,
`aws-sg`, `azure-nsg`, `kubernetes`.

Each exporter declares `Capabilities`. When a target cannot express something in
the policy (a `deny` rule for an allow-only cloud model, `reject` semantics, IPv6),
`compile` prints `LOSSY` warnings and exits non-zero unless `--allow-lossy` is passed.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy py2fw
```

## Roadmap

- **Done:** validate, compile (9 targets, capability-aware), analyze, graph,
  `explain`, `simulate`, `diff`, `compliance` (PCI/NIST/CIS mapping),
  port-range-aware IR, YAML source-line provenance in findings, optional
  reproducible hostname resolution with a lockfile.
- **Next:** GitOps action + PR comments, signed policy artifacts, egress/zone
  modeling to convert `review` compliance controls into `pass`/`fail`.
- **Later:** REST API, RBAC, drift detection, AI-assisted rule recommendation.

## Contact

info@sg2technologies.com

## License

Copyright © 2026 SG2 Technologies.

Licensed under the Apache License, Version 2.0. You may use, modify, and
redistribute this code — including commercially — under the terms of that
license.

## Author

Gopi Narayanaswamy — [github.com/ngopi37](https://github.com/ngopi37)
