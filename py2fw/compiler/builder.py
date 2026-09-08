from __future__ import annotations

from hashlib import sha256

from py2fw.compiler.ir import AddressIR, FirewallIR, PolicyIR, PortSpec, ServiceIR
from py2fw.compiler.resolver import resolve_rule_references
from py2fw.parser.schema import PolicyDocument


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


def build_ir(document: PolicyDocument) -> FirewallIR:
    resolved_addresses = resolve_rule_references(document)
    addresses = {
        name: AddressIR(name=name, values=values) for name, values in resolved_addresses.items()
    }
    services = {
        name: ServiceIR(
            name=name,
            protocol=service.protocol,
            ports=(
                PortSpec.all_ports() if service.protocol == "any" else _port_spec(service.port)
            ),
            description=service.description,
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
    )
