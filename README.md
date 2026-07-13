# Py2FW

Py2FW is a vendor-neutral firewall Policy-as-Code compiler. Security teams define policies once in YAML, validate and analyze them, then compile the same canonical policy into firewall vendor configurations.

```bash
py2fw validate examples/basic.yaml
py2fw analyze examples/basic.yaml
py2fw compile examples/basic.yaml --target fortigate
py2fw targets
py2fw graph examples/basic.yaml --output policy.svg
```

## Architecture

```text
YAML -> Parser -> Validator -> Internal Representation -> Exporter Plugin -> Vendor Config
```

Vendor logic is isolated in exporter plugins. Parsers, schema validation, resolvers, validators, analyzers, and optimizers operate only on vendor-neutral policy data and IR.

## Policy Example

```yaml
version: 1
objects:
  web:
    - 10.10.1.10
  db:
    - 10.10.2.10
services:
  mysql:
    protocol: tcp
    port: 3306
policies:
  - name: web_to_db
    source: [web]
    destination: [db]
    service: [mysql]
    action: allow
```

## Initial Targets

- `iptables`
- `nftables`
- `fortigate`
- `paloalto`
- `ciscoasa`
- `checkpoint`
- `aws-sg`
- `azure-nsg`
- `kubernetes`

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy py2fw
```

## Roadmap

Phase 1 includes validate, compile, analyze, and targets. Phase 2 adds richer graphing, explain, and diff. Later phases add GitOps, REST APIs, policy simulation, compliance mapping, multi-vendor deployment, AI rule recommendation, and optimization.
