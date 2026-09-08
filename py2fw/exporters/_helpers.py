from __future__ import annotations

from dataclasses import dataclass

from py2fw.compiler.ir import FirewallIR, PolicyIR, PortRange
from py2fw.compiler.query import address_values, resolves_to_any, service_values
from py2fw.utils.ip import is_ipv6

__all__ = [
    "Capabilities",
    "address_values",
    "describe_lossiness",
    "port_range_token",
    "resolves_to_any",
    "rule_comment",
    "service_values",
]


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What semantics a target can faithfully express.

    ``compile`` uses this to warn when an exporter must drop or downgrade
    something in the canonical policy.
    """

    allow_only: bool = False
    supports_reject: bool = False
    supports_ipv6: bool = True
    supports_ranges: bool = True


def rule_comment(rule: PolicyIR) -> str:
    return f"# {rule.name} ({rule.id})"


def port_range_token(prange: PortRange, sep: str) -> str:
    """Render a single range, e.g. ``80`` or ``1000<sep>2000``."""

    return str(prange.start) if prange.is_single else f"{prange.start}{sep}{prange.end}"


def describe_lossiness(ir: FirewallIR, caps: Capabilities) -> list[str]:
    warnings: list[str] = []
    for rule in ir.policies:
        if not rule.enabled:
            continue
        if caps.allow_only and rule.action != "allow":
            warnings.append(
                f"rule '{rule.name}': {rule.action} rule dropped "
                f"(target only expresses allow rules)"
            )
        if rule.action == "reject" and not caps.supports_reject:
            warnings.append(
                f"rule '{rule.name}': reject downgraded to deny/drop (target has no reject)"
            )
        if not caps.supports_ipv6:
            v6 = [v for v in address_values(ir, rule.source + rule.destination) if is_ipv6(v)]
            if v6:
                warnings.append(f"rule '{rule.name}': IPv6 addresses {v6} not supported by target")
    return warnings
