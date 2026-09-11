from __future__ import annotations

import ipaddress
from collections.abc import Callable

from py2fw.compiler.ir import FirewallIR, PortRange
from py2fw.exporters._helpers import Capabilities
from py2fw.plugins.base import Exporter


class FortiGateExporter(Exporter):
    name = "fortigate"
    description = "FortiGate CLI configuration"
    capabilities = Capabilities(supports_reject=False)

    def export(self, ir: FirewallIR) -> str:
        referenced = _referenced_addresses(ir)
        address_block, addr_name = _address_config(ir, referenced)
        blocks: list[str] = [*address_block, *_service_config(ir), "config firewall policy"]
        for index, rule in enumerate(ir.policies, start=1):
            if not rule.enabled:
                blocks.append(f"    # disabled {rule.name}")
                continue
            action = "accept" if rule.action == "allow" else "deny"
            src = " ".join(f'"{addr_name(n)}"' for n in rule.source)
            dst = " ".join(f'"{addr_name(n)}"' for n in rule.destination)
            svc = " ".join(f'"{_service_name(n)}"' for n in rule.services)
            blocks.extend(
                [
                    f"    edit {index}",
                    f'        set name "{rule.name}"',
                    '        set srcintf "any"',
                    '        set dstintf "any"',
                    f"        set srcaddr {src}",
                    f"        set dstaddr {dst}",
                    f"        set service {svc}",
                    f"        set action {action}",
                    '        set schedule "always"',
                    "        set logtraffic all",
                    "    next",
                ]
            )
        blocks.append("end")
        return "\n".join(blocks)


def _referenced_addresses(ir: FirewallIR) -> set[str]:
    names: set[str] = set()
    for rule in ir.policies:
        names.update(rule.source)
        names.update(rule.destination)
    return names


def _subnet(cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    return f"{net.network_address} {net.netmask}"


def _address_config(
    ir: FirewallIR, referenced: set[str]
) -> tuple[list[str], Callable[[str], str]]:
    addresses: list[str] = []
    groups: list[str] = []
    resolved: dict[str, str] = {}

    for name in sorted(referenced):
        address = ir.addresses.get(name)
        values = address.values if address else (name,)
        if values == ("any",):
            resolved[name] = "all"
            continue
        if len(values) == 1:
            addresses += [
                f'    edit "{name}"',
                f"        set subnet {_subnet(values[0])}",
                "    next",
            ]
            resolved[name] = name
            continue
        members: list[str] = []
        for idx, value in enumerate(values, start=1):
            member = f"{name}_{idx}"
            addresses += [
                f'    edit "{member}"',
                f"        set subnet {_subnet(value)}",
                "    next",
            ]
            members.append(member)
        member_list = " ".join('"' + m + '"' for m in members)
        groups += [f'    edit "{name}"', f"        set member {member_list}", "    next"]
        resolved[name] = name

    block: list[str] = []
    if addresses:
        block += ["config firewall address", *addresses, "end"]
    if groups:
        block += ["config firewall addrgrp", *groups, "end"]
    return block, lambda ref: resolved.get(ref, ref)


def _service_name(name: str) -> str:
    return "ALL" if name == "any" else name


def _forti_port(prange: PortRange) -> str:
    return str(prange.start) if prange.is_single else f"{prange.start}-{prange.end}"


def _service_config(ir: FirewallIR) -> list[str]:
    entries: list[str] = []
    for name, service in ir.services.items():
        if name == "any" or service.protocol == "any":
            continue
        entries.append(f'    edit "{name}"')
        if service.protocol in {"tcp", "udp"} and not service.ports.is_empty:
            ranges = " ".join(_forti_port(r) for r in service.ports.ranges)
            entries.append(f"        set {service.protocol}-portrange {ranges}")
        elif service.protocol == "icmp":
            entries.append("        set protocol ICMP")
        entries.append("    next")
    if not entries:
        return []
    return ["config firewall service custom", *entries, "end"]
