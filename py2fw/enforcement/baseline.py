"""Organisation security baseline with per-environment controls.

A baseline is owned by the security team, separately from the policies it
governs. ``defaults`` apply everywhere; an entry under ``environments`` overrides
scalar settings for that environment. Environment ``forbidden`` patterns and
``tests`` are *added* to the defaults, so an environment can never drop an
organisation-wide control.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from py2fw.analyzers.attack_surface import is_broad_source
from py2fw.analyzers.models import Finding, rule_finding
from py2fw.compiler.ir import FirewallIR, PolicyIR
from py2fw.compiler.query import address_values, service_values
from py2fw.parser.schema import FlowTestModel
from py2fw.parser.yaml_parser import ParseError, load_yaml

REQUIRABLE_FIELDS = ("description", "owner", "ticket")
DEFAULT_FAIL_ON = "high"
_T = TypeVar("_T")


class BaselineError(ValueError):
    """Raised when a baseline file is invalid or an environment is unknown."""


class ForbiddenModel(BaseModel):
    """An allow-rule pattern that must never be deployed."""

    model_config = ConfigDict(extra="forbid")

    name: str
    source: Literal["broad", "any"] | list[str] | None = None
    destination: Literal["any"] | list[str] | None = None
    protocol: Literal["tcp", "udp", "icmp"] | None = None
    ports: list[int] | None = None
    severity: Literal["low", "medium", "high", "critical"] = "high"
    description: str = ""


class ControlsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on: Literal["low", "medium", "high", "critical"] | None = None
    require_fields: list[str] | None = None
    allow_exceptions: bool | None = None
    max_exception_days: int | None = Field(default=None, ge=1)
    required_approvals: int | None = Field(default=None, ge=0)
    sign_approvals: bool | None = None
    allowed_targets: list[str] | None = None
    forbidden: list[ForbiddenModel] = Field(default_factory=list)
    tests: list[FlowTestModel] = Field(default_factory=list)

    @field_validator("require_fields")
    @classmethod
    def fields_are_known(cls, value: list[str] | None) -> list[str] | None:
        for name in value or []:
            if name not in REQUIRABLE_FIELDS:
                raise ValueError(
                    f"cannot require '{name}'; choose from {', '.join(REQUIRABLE_FIELDS)}"
                )
        return value


class BaselineModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    defaults: ControlsModel = Field(default_factory=ControlsModel)
    environments: dict[str, ControlsModel] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Controls:
    """The effective controls for one environment."""

    environment: str = ""
    fail_on: str = DEFAULT_FAIL_ON
    require_fields: tuple[str, ...] = ()
    allow_exceptions: bool = True
    max_exception_days: int | None = None
    required_approvals: int = 0
    sign_approvals: bool = False
    allowed_targets: tuple[str, ...] = ()
    forbidden: tuple[ForbiddenModel, ...] = ()
    tests: tuple[FlowTestModel, ...] = ()
    baseline_sha256: str = ""
    source: str = field(default="built-in defaults")

    def target_allowed(self, target: str) -> bool:
        return not self.allowed_targets or target in self.allowed_targets


def load_baseline(path: Path) -> BaselineModel:
    try:
        return BaselineModel.model_validate(load_yaml(path))
    except ParseError as exc:
        raise BaselineError(f"baseline {path}: {exc}") from exc
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise BaselineError(f"baseline {path}: {details}") from exc


def _setting(layers: list[ControlsModel], name: str, default: _T) -> _T:
    """The most specific layer's explicit value for ``name``, else ``default``."""

    value = default
    for layer in layers:
        if getattr(layer, name) is not None:
            value = cast(_T, getattr(layer, name))
    return value


def resolve_controls(
    baseline: BaselineModel | None,
    environment: str = "",
    *,
    baseline_sha256: str = "",
    source: str = "built-in defaults",
) -> Controls:
    if baseline is None:
        return Controls(environment=environment)
    layers = [baseline.defaults]
    if environment:
        if baseline.environments and environment not in baseline.environments:
            known = ", ".join(sorted(baseline.environments))
            raise BaselineError(f"unknown environment '{environment}' (baseline defines: {known})")
        if environment in baseline.environments:
            layers.append(baseline.environments[environment])

    return Controls(
        environment=environment,
        fail_on=_setting(layers, "fail_on", DEFAULT_FAIL_ON),
        require_fields=tuple(_setting(layers, "require_fields", list[str]())),
        allow_exceptions=_setting(layers, "allow_exceptions", True),
        max_exception_days=_setting(layers, "max_exception_days", cast(int | None, None)),
        required_approvals=_setting(layers, "required_approvals", 0),
        sign_approvals=_setting(layers, "sign_approvals", False),
        allowed_targets=tuple(_setting(layers, "allowed_targets", list[str]())),
        forbidden=tuple(item for layer in layers for item in layer.forbidden),
        tests=tuple(item for layer in layers for item in layer.tests),
        baseline_sha256=baseline_sha256,
        source=source,
    )


def _overlaps(values: tuple[str, ...], cidrs: list[str]) -> bool:
    if "any" in values:
        return True
    for value in values:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        for cidr in cidrs:
            other = ipaddress.ip_network(cidr, strict=False)
            if net.version == other.version and net.overlaps(other):
                return True
    return False


def _matches(ir: FirewallIR, rule: PolicyIR, pattern: ForbiddenModel) -> bool:
    sources = address_values(ir, rule.source)
    if pattern.source == "broad" and not is_broad_source(sources):
        return False
    if pattern.source == "any" and "any" not in sources:
        return False
    if isinstance(pattern.source, list) and not _overlaps(sources, pattern.source):
        return False

    destinations = address_values(ir, rule.destination)
    if pattern.destination == "any" and "any" not in destinations:
        return False
    if isinstance(pattern.destination, list) and not _overlaps(destinations, pattern.destination):
        return False

    services = service_values(ir, rule.services)
    if pattern.protocol is not None:
        services = tuple(s for s in services if s.protocol in (pattern.protocol, "any"))
        if not services:
            return False
    if pattern.ports is not None:
        return any(svc.ports.contains(port) for svc in services for port in pattern.ports)
    return True


def enforce_baseline(ir: FirewallIR, controls: Controls) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ir.policies:
        if not rule.enabled:
            continue
        for name in controls.require_fields:
            if not getattr(rule, name):
                findings.append(
                    rule_finding(
                        rule,
                        "high",
                        f"Baseline: missing {name}",
                        f"Required in {controls.environment or 'all environments'}.",
                    )
                )
        if rule.action != "allow":
            continue
        for pattern in controls.forbidden:
            if _matches(ir, rule, pattern):
                findings.append(
                    rule_finding(
                        rule,
                        pattern.severity,
                        f"Baseline: {pattern.name}",
                        pattern.description or "Rule matches a forbidden baseline pattern.",
                    )
                )
    return findings
