"""Security regression tests: flows whose decision must never change."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from py2fw.compiler.ir import FirewallIR
from py2fw.engine.evaluate import Flow, evaluate
from py2fw.parser.schema import FlowTestModel

# Documentation ranges (RFC 5737 / RFC 3849) stand in for "somewhere on the internet".
_INTERNET_PROBE = {4: "203.0.113.10", 6: "2001:db8::10"}


@dataclass(frozen=True, slots=True)
class FlowTestResult:
    name: str
    origin: str  # "policy" | "baseline"
    passed: bool
    detail: str
    location: str = ""
    line: int | None = None


def _probes(value: str) -> list[str]:
    """Representative addresses for one address value: first and last usable host."""

    if value == "any":
        return [_INTERNET_PROBE[4]]
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return []
    if net.num_addresses <= 2:
        return [str(net.network_address)]
    hosts = [net.network_address + 1, net.broadcast_address - 1]
    return list(dict.fromkeys(str(host) for host in hosts))


def _endpoints(ir: FirewallIR, value: str) -> list[str]:
    if value == "*":
        values = [v for address in ir.addresses.values() for v in address.values]
        return list(dict.fromkeys(p for v in values if v != "any" for p in _probes(v)))
    if value in ir.addresses:
        return list(dict.fromkeys(p for v in ir.addresses[value].values for p in _probes(v)))
    return [value]


def _describe(flow: Flow) -> str:
    target = flow.protocol if flow.port is None else f"{flow.protocol}/{flow.port}"
    return f"{flow.source} -> {flow.destination} {target}"


def run_flow_tests(
    ir: FirewallIR, tests: Iterable[FlowTestModel], origin: str
) -> list[FlowTestResult]:
    results: list[FlowTestResult] = []
    for index, test in enumerate(tests):
        location = f"tests[{index}]" if origin == "policy" else f"baseline tests[{index}]"
        line = ir.source_map.line(location) if origin == "policy" else None
        sources, destinations = _endpoints(ir, test.src), _endpoints(ir, test.dst)
        if not sources or not destinations:
            results.append(
                FlowTestResult(
                    test.name, origin, False, "no addresses to probe", location, line
                )
            )
            continue
        failure = ""
        probes = 0
        for src in sources:
            for dst in destinations:
                try:
                    if ipaddress.ip_address(src).version != ipaddress.ip_address(dst).version:
                        continue
                except ValueError:
                    failure = f"not an IP address: {src if '/' in src else dst}"
                    break
                flow = Flow(src, dst, test.protocol, test.port)
                decision = evaluate(ir, flow)
                probes += 1
                actual = "allow" if decision.allowed else "deny"
                if actual != test.expect:
                    by = decision.matched_rule.name if decision.matched_rule else "default deny"
                    failure = f"{_describe(flow)} is {actual} by {by}, expected {test.expect}"
                    break
            if failure:
                break
        detail = failure or f"{probes} flow(s) got {test.expect} as expected"
        results.append(FlowTestResult(test.name, origin, not failure, detail, location, line))
    return results
