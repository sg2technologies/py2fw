from __future__ import annotations

from hashlib import sha256

from py2fw.compiler.ir import AddressIR, FirewallIR, PolicyIR, ServiceIR
from py2fw.compiler.resolver import resolve_rule_references
from py2fw.parser.schema import PolicyDocument


def _ports(value: int | str | list[int] | None) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, int):
        return (value,)
    if isinstance(value, list):
        return tuple(value)
    if "-" in value:
        start, end = value.split("-", 1)
        return tuple(range(int(start), int(end) + 1))
    return (int(value),)


def _rule_id(name: str, index: int) -> str:
    digest = sha256(f"{index}:{name}".encode("utf-8")).hexdigest()[:12]
    return f"rule-{digest}"


def build_ir(document: PolicyDocument) -> FirewallIR:
    resolved_addresses = resolve_rule_references(document)
    addresses = {
        name: AddressIR(name=name, values=values)
        for name, values in resolved_addresses.items()
    }
    services = {
        name: ServiceIR(
            name=name,
            protocol=service.protocol,
            ports=_ports(service.port),
            description=service.description,
        )
        for name, service in document.services.items()
    }
    services["any"] = ServiceIR(name="any", protocol="any")

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
    return FirewallIR(version=document.version, addresses=addresses, services=services, policies=policies)
