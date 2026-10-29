from __future__ import annotations

from py2fw.compiler.ir import FirewallIR, ServiceIR
from py2fw.exporters import _syntax
from py2fw.exporters._helpers import (
    Capabilities,
    address_values,
    port_range_token,
    rule_comment,
    service_values,
)
from py2fw.plugins.base import Exporter
from py2fw.utils.ip import is_ipv6

_TARGET = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}


class IptablesExporter(Exporter):
    name = "iptables"
    description = "Linux iptables / ip6tables rules"
    capabilities = Capabilities(supports_reject=True)

    def check_syntax(self, rendered: str) -> list[str]:
        problems: list[str] = []
        for section in rendered.split("\n\n"):
            lines = [line for line in section.splitlines() if line.strip()]
            if lines and lines[0] == "# ip6tables-restore":
                lines = lines[1:]
            if not lines or lines[0] != "*filter" or lines[-1] != "COMMIT":
                problems.append("each table must start with '*filter' and end with 'COMMIT'")
        return problems + _syntax.line_grammar(
            rendered,
            [
                r"\*filter",
                r"COMMIT",
                r"#.*",
                r":(INPUT|FORWARD|OUTPUT) (ACCEPT|DROP) \[0:0\]",
                r"-A FORWARD( -p (tcp|udp|icmp))?( -s \S+)?( -d \S+)?( --dport \d+(:\d+)?)?"
                r" -j (ACCEPT|DROP|REJECT)",
            ],
        )

    def native_checks(self, rendered: str) -> list[tuple[tuple[str, ...], str]]:
        v4, _, v6 = rendered.partition("\n\n# ip6tables-restore\n")
        checks: list[tuple[tuple[str, ...], str]] = [(("iptables-restore", "--test"), v4 + "\n")]
        if v6:
            checks.append((("ip6tables-restore", "--test"), v6 + "\n"))
        return checks

    def export(self, ir: FirewallIR) -> str:
        v4 = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [0:0]"]
        v6 = list(v4)
        for rule in ir.policies:
            if not rule.enabled:
                v4.append(f"{rule_comment(rule)} disabled")
                continue
            target = _TARGET.get(rule.action, "DROP")
            for src in address_values(ir, rule.source):
                for dst in address_values(ir, rule.destination):
                    for service in service_values(ir, rule.services):
                        bucket = v6 if is_ipv6(src) or is_ipv6(dst) else v4
                        for line in _rule_lines(rule.name, target, src, dst, service):
                            bucket.append(f"{rule_comment(rule)}")
                            bucket.append(line)
        v4.append("COMMIT")
        sections = ["\n".join(v4)]
        if len(v6) > 4:
            v6.append("COMMIT")
            sections.append("# ip6tables-restore\n" + "\n".join(v6))
        return "\n\n".join(sections)


def _rule_lines(name: str, target: str, src: str, dst: str, service: ServiceIR) -> list[str]:
    proto = "" if service.protocol == "any" else f" -p {service.protocol}"
    src_arg = "" if src == "any" else f" -s {src}"
    dst_arg = "" if dst == "any" else f" -d {dst}"
    port_tokens = (
        [""]
        if service.ports.is_empty or service.ports.is_all_ports
        else [f" --dport {port_range_token(r, ':')}" for r in service.ports.ranges]
    )
    return [f"-A FORWARD{proto}{src_arg}{dst_arg}{dport} -j {target}" for dport in port_tokens]
