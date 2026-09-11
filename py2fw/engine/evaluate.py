from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from py2fw.compiler.ir import FirewallIR, PolicyIR
from py2fw.compiler.query import address_values, service_values

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class Flow:
    """A single packet/connection to evaluate against a policy."""

    source: str
    destination: str
    protocol: str = "tcp"
    port: int | None = None

    @property
    def source_ip(self) -> IpAddress:
        return ipaddress.ip_address(self.source)

    @property
    def destination_ip(self) -> IpAddress:
        return ipaddress.ip_address(self.destination)


@dataclass(frozen=True, slots=True)
class RuleTrace:
    rule: str
    matched: bool
    reason: str


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    action: str
    matched_rule: PolicyIR | None
    default_applied: bool
    trace: tuple[RuleTrace, ...] = field(default_factory=tuple)

    @property
    def verdict(self) -> str:
        return "ALLOWED" if self.allowed else "DENIED"


def _addr_contains(selector_values: tuple[str, ...], target: IpAddress) -> bool:
    for value in selector_values:
        if value == "any":
            return True
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if target.version == network.version and target in network:
            return True
    return False


def _service_matches(ir: FirewallIR, service_names: tuple[str, ...], flow: Flow) -> bool:
    for service in service_values(ir, service_names):
        if service.protocol not in ("any", flow.protocol):
            continue
        if service.protocol == "any" or service.ports.is_all_ports:
            return True
        if flow.protocol == "icmp":
            return service.protocol in ("icmp", "any")
        if flow.port is not None and service.ports.contains(flow.port):
            return True
        if flow.port is None and service.ports.is_empty:
            return True
    return False


def _match_reason(ir: FirewallIR, rule: PolicyIR, flow: Flow) -> tuple[bool, str]:
    if not rule.enabled:
        return False, "rule is disabled"
    if not _addr_contains(address_values(ir, rule.source), flow.source_ip):
        return False, f"source {flow.source} not in {list(rule.source)}"
    if not _addr_contains(address_values(ir, rule.destination), flow.destination_ip):
        return False, f"destination {flow.destination} not in {list(rule.destination)}"
    if not _service_matches(ir, rule.services, flow):
        target = flow.protocol if flow.port is None else f"{flow.protocol}/{flow.port}"
        return False, f"service {target} not in {list(rule.services)}"
    return True, f"matched {rule.action} rule"


def evaluate(ir: FirewallIR, flow: Flow) -> Decision:
    """Return the first-match decision for ``flow`` against ``ir``."""

    trace: list[RuleTrace] = []
    for rule in ir.policies:
        matched, reason = _match_reason(ir, rule, flow)
        trace.append(RuleTrace(rule=rule.name, matched=matched, reason=reason))
        if matched:
            return Decision(
                allowed=rule.action == "allow",
                action=rule.action,
                matched_rule=rule,
                default_applied=False,
                trace=tuple(trace),
            )
    return Decision(
        allowed=False,
        action="deny",
        matched_rule=None,
        default_applied=True,
        trace=tuple(trace),
    )
