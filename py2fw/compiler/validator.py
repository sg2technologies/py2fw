from __future__ import annotations

from dataclasses import dataclass

from py2fw.parser.schema import PolicyDocument
from py2fw.parser.source_map import SourceMap
from py2fw.utils.constants import VALID_ACTIONS, VALID_PROTOCOLS
from py2fw.utils.ip import is_hostname, is_valid_endpoint


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    severity: str
    message: str
    location: str
    line: int | None = None


class ValidationResult:
    def __init__(
        self, issues: list[ValidationIssue] | None = None, source: SourceMap | None = None
    ) -> None:
        self.issues = issues or []
        self.source = source or SourceMap()

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def add(self, severity: str, message: str, location: str) -> None:
        self.issues.append(
            ValidationIssue(severity, message, location, self.source.line(location))
        )


def _validate_port(
    value: int | str | list[int] | None, result: ValidationResult, name: str
) -> None:
    ports: list[int]
    if value is None:
        return
    if isinstance(value, int):
        ports = [value]
    elif isinstance(value, list):
        ports = value
    elif isinstance(value, str) and "-" in value:
        start_raw, end_raw = value.split("-", 1)
        if not start_raw.isdigit() or not end_raw.isdigit():
            result.add("error", "invalid port range", f"services.{name}.port")
            return
        start, end = int(start_raw), int(end_raw)
        if start > end:
            result.add("error", "port range start must be <= end", f"services.{name}.port")
            return
        ports = [start, end]
    elif isinstance(value, str) and value.isdigit():
        ports = [int(value)]
    else:
        result.add("error", "invalid port value", f"services.{name}.port")
        return
    for port in ports:
        if port < 1 or port > 65535:
            result.add("error", f"port out of range: {port}", f"services.{name}.port")


def validate_document(
    document: PolicyDocument, source: SourceMap | None = None
) -> ValidationResult:
    result = ValidationResult(source=source)

    for name, values in document.objects.items():
        if not values:
            result.add("error", "object must contain at least one endpoint", f"objects.{name}")
        seen_values: set[str] = set()
        for index, value in enumerate(values):
            loc = f"objects.{name}[{index}]"
            if value in seen_values:
                result.add("warning", f"duplicate object value: {value}", loc)
            seen_values.add(value)
            if not is_valid_endpoint(value):
                result.add("error", f"invalid IP, CIDR, or hostname: {value}", loc)
            elif is_hostname(value):
                result.add(
                    "warning",
                    f"hostname '{value}' is passed through literally; pin to IP/CIDR or "
                    f"compile with --resolve-hosts",
                    loc,
                )

    for name, members in document.groups.items():
        if not members:
            result.add("error", "group must not be empty", f"groups.{name}")
        for member in members:
            if member not in document.objects and member not in document.groups and member != "any":
                result.add("error", f"unknown group member: {member}", f"groups.{name}")

    service_defs: set[tuple[str, str]] = set()
    for name, service in document.services.items():
        if service.protocol not in VALID_PROTOCOLS:
            result.add("error", f"invalid protocol: {service.protocol}", f"services.{name}")
        _validate_port(service.port, result, name)
        fingerprint = (service.protocol, str(service.port))
        if fingerprint in service_defs:
            result.add("warning", "duplicate service definition", f"services.{name}")
        service_defs.add(fingerprint)

    rule_names: set[str] = set()
    for index, rule in enumerate(document.policies):
        location = f"policies[{index}]"
        if rule.name in rule_names:
            result.add("warning", f"duplicate rule name: {rule.name}", location)
        rule_names.add(rule.name)
        if not rule.source:
            result.add("error", "missing source", f"{location}.source")
        if not rule.destination:
            result.add("error", "missing destination", f"{location}.destination")
        if not rule.service:
            result.add("error", "missing service", f"{location}.service")
        if rule.action not in VALID_ACTIONS:
            result.add("error", f"invalid action: {rule.action}", f"{location}.action")
        for ref in (*rule.source, *rule.destination):
            if ref not in document.objects and ref not in document.groups and ref != "any":
                result.add("error", f"unknown object reference: {ref}", location)
        for service_ref in rule.service:
            if service_ref not in document.services and service_ref != "any":
                result.add("error", f"unknown service reference: {service_ref}", location)

    return result
