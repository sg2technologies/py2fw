from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AddressIR:
    name: str
    values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceIR:
    name: str
    protocol: str
    ports: tuple[int, ...] = field(default_factory=tuple)
    description: str = ""


@dataclass(frozen=True, slots=True)
class PolicyIR:
    id: str
    name: str
    source: tuple[str, ...]
    destination: tuple[str, ...]
    services: tuple[str, ...]
    action: str
    enabled: bool
    description: str


@dataclass(frozen=True, slots=True)
class FirewallIR:
    version: int
    addresses: dict[str, AddressIR]
    services: dict[str, ServiceIR]
    policies: tuple[PolicyIR, ...]
