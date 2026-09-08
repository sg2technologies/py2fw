# Architecture

```text
YAML -> Parser -> Validator -> IR Builder -> Optimizer -> Exporter Plugin
                                   |
                                   +-> Evaluation Engine (engine/evaluate.py)
                                   +-> Diff Engine        (engine/diff.py)
                                   +-> Analyzers          (analyzers/)
```

The parser and validator are vendor-neutral. They understand only the Py2FW
policy schema, object references, services and rule semantics.

## Internal Representation

`compiler/ir.py` defines `FirewallIR` (canonical addresses, services, policies,
group membership) plus `PortSpec` / `PortRange`, which model port ranges as
first-class ranges rather than expanded integer sets.

Read-only IR queries (resolve address/group names to values, resolve services)
live in `compiler/query.py` so exporters and analyzers share them without
depending on each other.

## Source provenance

`parser/source_map.py` composes the YAML into a node tree and records a
1-indexed line for every logical location (`policies[2].source`, `objects.web[0]`,
`services.https.port`). The map is threaded into `validate_document` and
`build_ir`, so `ValidationIssue`, every `Finding`, and `PolicyIR`/`AddressIR`/
`ServiceIR` carry a `line`. `SourceMap.line()` walks up to the nearest known
ancestor when an exact path is not present.

## Hostname resolution

`compiler/hosts.py` resolves hostnames used in objects. By default they are left
literal (with a validation warning). With `--resolve-hosts`, names are resolved
via DNS once, pinned in `<policy>.py2fw-lock.json`, and reused on later compiles
unless `--refresh-hosts` is given. The resolver is injectable for testing.

## Plugin Contract

```python
class Exporter:
    name = "vendor"
    capabilities = Capabilities(allow_only=False, supports_reject=False, ...)

    def export(self, ir: FirewallIR) -> str: ...
```

`Capabilities` drives the lossiness warnings emitted by `compile`. Built-ins are
registered in `plugins/registry.load_builtin_exporters`; external plugins can be
added through entry points without touching compiler internals.

## Evaluation Engine

`engine/evaluate.py` implements first-match evaluation with CIDR containment and
port-range matching, returning a `Decision` with a per-rule trace. `simulate`,
`explain` and semantic shadow-rule detection all build on it. `engine/diff.py`
compares two compiled policies at the semantic (resolved) level and scores the
security impact of the change.

## Scale Notes

Policy order is preserved because firewall rule order is security-significant.
Resolver output is de-duplicated while keeping first-seen ordering. Optimizer
passes must be explicit, benchmarked, and prove semantic equivalence before
altering rule order.
