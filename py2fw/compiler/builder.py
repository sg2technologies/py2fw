from __future__ import annotations

from hashlib import sha256

from py2fw.compiler.ir import AddressIR, FirewallIR, PolicyIR, PortSpec, ServiceIR
from py2fw.compiler.resolver import resolve_rule_references
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.source_map import SourceMap


def _port_spec(value: int | str | list[int] | None) -> PortSpec:
    if value is None:
        return PortSpec()
    if isinstance(value, int):
        return PortSpec.from_pairs([(value, value)])
    if isinstance(value, list):
        return PortSpec.from_pairs([(port, port) for port in value])
    if "-" in value:
        start, end = value.split("-", 1)
        return PortSpec.from_pairs([(int(start), int(end))])
    return PortSpec.from_pairs([(int(value), int(value))])


def _rule_id(name: str, index: int) -> str:
    digest = sha256(f"{index}:{name}".encode()).hexdigest()[:12]
    return f"rule-{digest}"


def _expand_hosts(
    values: tuple[str, ...], host_map: dict[str, tuple[str, ...]]
) -> tuple[str, ...]:
    if not host_map:
        return values
    expanded: list[str] = []
    for value in values:
        expanded.extend(host_map.get(value, (value,)))
    return tuple(dict.fromkeys(expanded))


def build_ir(
    document: PolicyDocument,
    source_map: SourceMap | None = None,
    *,
    host_map: dict[str, tuple[str, ...]] | None = None,
) -> FirewallIR:
    source = source_map or SourceMap()
    hosts = host_map or {}
    resolved_addresses = resolve_rule_references(document)

    def address_line(name: str) -> int | None:
        kind = "objects" if name in document.objects else "groups"
        return source.line(f"{kind}.{name}")

    addresses = {
        name: AddressIR(name=name, values=_expand_hosts(values, hosts), line=address_line(name))
        for name, values in resolved_addresses.items()
    }
    services = {
        name: ServiceIR(
            name=name,
            protocol=service.protocol,
            ports=PortSpec.all_ports() if service.protocol == "any" else _port_spec(service.port),
            description=service.description,
            line=source.line(f"services.{name}"),
        )
        for name, service in document.services.items()
    }
    services["any"] = ServiceIR(name="any", protocol="any", ports=PortSpec.all_ports())

    policies = tuple(
        PolicyIR(
            id=_rule_id(rule.name, index),
            name=rule.name,
            source=tuple(rule.source),
            destination=tuple(rule.destination),
            services=tuple(rule.service),
            action=rule.action,
            enabled=rule.enabled,
            description=rule.description,
            line=source.line(f"policies[{index}]"),
            location=f"policies[{index}]",
        )
        for index, rule in enumerate(document.policies)
    )
    groups = {name: tuple(members) for name, members in document.groups.items()}
    return FirewallIR(
        version=document.version,
        addresses=addresses,
        services=services,
        policies=policies,
        groups=groups,
        source_map=source,
    )
