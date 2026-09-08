# Py2FW

Py2FW is a vendor-neutral firewall Policy-as-Code compiler. Security teams define
policy once in YAML, then **validate → analyze → simulate → diff → compile** it
into vendor configurations — verifying intent before anything reaches a device.

```bash
py2fw validate examples/basic.yaml
py2fw analyze  examples/basic.yaml
py2fw simulate examples/basic.yaml --src 10.10.1.10 --dst 10.10.2.10 --port 3306
py2fw explain  examples/basic.yaml --src 10.10.1.10 --dst 10.10.2.10 --port 3306
py2fw diff     examples/basic.yaml examples/basic-v2.yaml
py2fw compile  examples/basic.yaml --target fortigate
py2fw targets
py2fw graph    examples/basic.yaml --output policy.svg
```

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
  `explain`, `simulate`, `diff`, port-range-aware IR.
- **Next:** source-location provenance in findings, real compliance mapping
  (NIST/PCI/CIS), GitOps action + PR comments, signed policy artifacts.
- **Later:** REST API, RBAC, drift detection, AI-assisted rule recommendation.
