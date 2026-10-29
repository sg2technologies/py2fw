"""Validate a generated vendor configuration before it can be deployed.

* **syntax** - the exporter's own grammar/structure check, plus the vendor's
  CLI validator (``iptables-restore --test``, ``nft -c``) when requested.
* **intent** - the configuration is compared with the IR it was generated from:
  every address and port an enabled rule needs must appear in it, and it must not
  reference any address the policy does not define. This is a target-neutral,
  token-level comparison; it catches dropped rules, dropped scope and injected
  addresses, while rule order and decisions are covered by the regression tests.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass

from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.query import address_values, service_values
from py2fw.plugins.base import Exporter

_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]*(?![\w:])")
_NUMBER = re.compile(r"(?<![\w.])\d{1,5}(?![\w.])")


@dataclass(frozen=True, slots=True)
class ConfigCheck:
    kind: str  # "syntax" | "native-syntax" | "intent"
    passed: bool
    detail: str


def check_syntax(
    exporter: Exporter, rendered: str, *, native: bool = False
) -> list[ConfigCheck]:
    problems = exporter.check_syntax(rendered)
    checks = [ConfigCheck("syntax", not problems, "; ".join(problems) or "well-formed")]
    if native:
        checks.extend(_native(exporter, rendered))
    return checks


def _native(exporter: Exporter, rendered: str) -> list[ConfigCheck]:
    commands = exporter.native_checks(rendered)
    if not commands:
        return [ConfigCheck("native-syntax", False, f"no vendor validator for {exporter.name}")]
    checks: list[ConfigCheck] = []
    for command, stdin in commands:
        if shutil.which(command[0]) is None:
            checks.append(ConfigCheck("native-syntax", False, f"{command[0]} not found on PATH"))
            continue
        proc = subprocess.run(
            list(command), input=stdin, capture_output=True, text=True, timeout=60, check=False
        )
        output = (proc.stderr or proc.stdout).strip()
        checks.append(
            ConfigCheck(
                "native-syntax",
                proc.returncode == 0,
                f"{' '.join(command)}: " + (output or "ok"),
            )
        )
    return checks


def _known_tokens(ir: FirewallIR) -> set[str]:
    """Every address string a faithful export may legitimately contain."""

    known = {"0.0.0.0", "::"}
    for address in ir.addresses.values():
        for value in address.values:
            if value == "any":
                continue
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            known |= {str(net.network_address), str(net.netmask), str(net.hostmask)}
    return known


def check_intent(ir: FirewallIR, exporter: Exporter, rendered: str) -> ConfigCheck:
    caps = exporter.capabilities
    present = set(_IPV4.findall(rendered)) | {
        str(ipaddress.ip_address(m)) for m in _IPV6.findall(rendered) if _is_ip(m)
    }
    numbers = set(_NUMBER.findall(_IPV6.sub(" ", _IPV4.sub(" ", rendered))))

    problems: list[str] = []
    for rule in ir.policies:
        if not rule.enabled or (caps.allow_only and rule.action != "allow"):
            continue
        sides = rule.source + (rule.destination if caps.scopes_destination else ())
        for value in address_values(ir, sides):
            if value == "any":
                continue
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if str(net.network_address) not in present:
                problems.append(f"rule {rule.name}: address {value} missing")
        for service in service_values(ir, rule.services):
            if service.ports.is_all_ports:
                continue
            for prange in service.ports.ranges:
                for port in {prange.start, prange.end}:
                    if str(port) not in numbers:
                        problems.append(f"rule {rule.name}: port {port} missing")

    unexpected = sorted(present - _known_tokens(ir))
    if unexpected:
        problems.append(f"addresses not defined in the policy: {', '.join(unexpected)}")
    return ConfigCheck("intent", not problems, "; ".join(problems) or "matches policy")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
