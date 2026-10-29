# Py2FW

Py2FW is a vendor-neutral firewall Policy-as-Code compiler. Security teams define
policy once in YAML, then **validate → analyze → simulate → diff → compile** it
into vendor configurations — verifying intent before anything reaches a device.

```bash
py2fw validate   examples/basic.yaml
py2fw check      examples/prod.yaml -b examples/baseline.yaml   # gate (CI)
py2fw test       examples/prod.yaml -b examples/baseline.yaml   # regression flows
py2fw verify     examples/prod.yaml -t paloalto # syntax + config-vs-intent
py2fw analyze    examples/basic.yaml
py2fw compliance examples/basic.yaml            # PCI DSS / NIST 800-53 / CIS
py2fw simulate   examples/basic.yaml --src 10.10.1.10 --dst 10.10.2.10 --port 3306
py2fw explain    examples/basic.yaml --src 10.10.1.10 --dst 10.10.2.10 --port 3306
py2fw diff       examples/basic.yaml examples/basic-v2.yaml
py2fw compile    examples/basic.yaml --target fortigate
py2fw targets
py2fw graph      examples/basic.yaml --output policy.svg
```

Review, approval and controlled deployment:

```bash
py2fw plan    examples/prod.yaml -t paloalto -b examples/baseline.yaml --author alice
py2fw approve py2fw-plan.json --by bob
py2fw approve py2fw-plan.json --by carol
py2fw deploy  py2fw-plan.json --actor ci --to build/prod.cfg
py2fw audit verify
```

`validate` and `analyze` report the **source line** of every issue.

A change only reaches production after it passes eight stages: parsing,
schema validation, semantic security checks, enforcement of an organisation
**baseline** with per-environment controls, config generation, config
validation (syntax, comparison with the policy, regression flow tests),
review and approval (diff, N approvers, no self-approval), and a
re-verified deployment recorded in a hash-chained audit log. Every finding is
a **violation** (blocks) or a **warning** (advisory). See
[docs/guardrails.md](docs/guardrails.md).
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
  `check` deployment gate with time-boxed exceptions, security baseline with
  environment controls, regression flow tests, config syntax and intent
  verification, `plan`/`approve`/`deploy` with a tamper-evident audit log,
  port-range-aware IR, YAML source-line provenance in findings, optional
  reproducible hostname resolution with a lockfile.
- **Next:** GitOps action + PR comments, egress/zone
  modeling to convert `review` compliance controls into `pass`/`fail`.

## Enterprise

REST API, RBAC, drift detection, and AI-assisted rule recommendation are
available as part of Py2FW Enterprise. Contact SG2 Technologies to learn more:
[sg2technologies.com](https://sg2technologies.com) · info@sg2technologies.com

## Contact

[sg2technologies.com](https://sg2technologies.com) · info@sg2technologies.com

## License

Copyright © 2026 SG2 Technologies.

Licensed under the Apache License, Version 2.0. You may use, modify, and
redistribute this code — including commercially — under the terms of that
license.

## Author

Gopi Narayanaswamy — [github.com/ngopi37](https://github.com/ngopi37)
