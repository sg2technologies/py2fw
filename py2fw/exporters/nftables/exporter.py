from __future__ import annotations

from py2fw.compiler.ir import FirewallIR, ServiceIR
from py2fw.exporters._helpers import (
    Capabilities,
    address_values,
    port_range_token,
    service_values,
)
from py2fw.plugins.base import Exporter
from py2fw.utils.ip import is_ipv6

_VERDICT = {"allow": "accept", "deny": "drop", "reject": "reject"}


class NftablesExporter(Exporter):
    name = "nftables"
    description = "Linux nftables ruleset"
    capabilities = Capabilities(supports_reject=True)

    def export(self, ir: FirewallIR) -> str:
        lines = [
            "table inet py2fw {",
            "  chain forward {",
            "    type filter hook forward priority 0; policy drop;",
        ]
        for rule in ir.policies:
            if not rule.enabled:
                lines.append(f"    # disabled: {rule.name}")
                continue
            verdict = _VERDICT.get(rule.action, "drop")
            for src in address_values(ir, rule.source):
                for dst in address_values(ir, rule.destination):
                    for service in service_values(ir, rule.services):
                        for match in _matches(src, dst, service):
                            body = f"{match} " if match else ""
                            lines.append(f'    {body}counter {verdict} comment "{rule.name}"')
        lines.extend(["  }", "}"])
        return "\n".join(lines)


def _matches(src: str, dst: str, service: ServiceIR) -> list[str]:
    fam = "ip6" if is_ipv6(src) or is_ipv6(dst) else "ip"
    parts: list[str] = []
    if src != "any":
        parts.append(f"{fam} saddr {src}")
    if dst != "any":
        parts.append(f"{fam} daddr {dst}")
    prefix = " ".join(parts)
    if service.protocol == "any" or service.ports.is_all_ports:
        return [prefix]
    if service.ports.is_empty:
        return [f"{prefix} meta l4proto {service.protocol}".strip()]
    return [
        f"{prefix} {service.protocol} dport {port_range_token(r, '-')}".strip()
        for r in service.ports.ranges
    ]
