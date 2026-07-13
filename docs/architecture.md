# Architecture

Py2FW uses a clean compiler pipeline:

```text
YAML -> Parser -> Validator -> IR Builder -> Optimizer -> Exporter Plugin
```

The parser and validator are intentionally vendor-neutral. They only understand Py2FW policy schema, object references, services, and rule semantics.

## Internal Representation

`FirewallIR` contains canonical address, service, and policy records. Exporters receive only this IR and must not parse YAML or inspect parser models.

## Plugin Contract

Exporters implement `py2fw.plugins.base.Exporter`:

```python
class Exporter:
    name = "vendor"

    def export(self, ir: FirewallIR) -> str:
        ...
```

Built-ins are registered in `py2fw.plugins.registry.load_builtin_exporters`. External plugins can later be loaded through Python entry points without changing compiler internals.

## Scale Notes

Policy order is preserved because firewall rule order is security-significant. Resolver output is deduplicated while keeping first-seen ordering. Future optimizer passes should be explicit, benchmarked, and prove semantic equivalence before altering rule order.
