from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from py2fw.parser.source_map import SourceMap

MIN_PORT = 1
MAX_PORT = 65535


@dataclass(frozen=True, slots=True, order=True)
class PortRange:
    """An inclusive port range. ``start == end`` represents a single port."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start > self.end:
            raise ValueError(f"port range start {self.start} > end {self.end}")

    @property
    def is_single(self) -> bool:
        return self.start == self.end

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end

    def overlaps(self, other: PortRange) -> bool:
        return self.start <= other.end and other.start <= self.end


def normalize_ranges(ranges: Iterable[PortRange]) -> tuple[PortRange, ...]:
    """Sort and merge adjacent/overlapping ranges into a canonical tuple."""

    ordered = sorted(ranges)
    merged: list[PortRange] = []
    for current in ordered:
        if merged and current.start <= merged[-1].end + 1:
            last = merged[-1]
            merged[-1] = PortRange(last.start, max(last.end, current.end))
        else:
            merged.append(current)
    return tuple(merged)


@dataclass(frozen=True, slots=True)
class PortSpec:
    """A canonical set of ports, stored as sorted non-overlapping ranges.

    An empty spec means "no port concept" (icmp). A spec equal to the full
    ``1-65535`` range means "every port" (protocol ``any`` / all-ports services).
    """

    ranges: tuple[PortRange, ...] = ()

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[int, int]]) -> PortSpec:
        return cls(normalize_ranges(PortRange(start, end) for start, end in pairs))

    @classmethod
    def all_ports(cls) -> PortSpec:
        return cls((PortRange(MIN_PORT, MAX_PORT),))

    @property
    def is_empty(self) -> bool:
        return not self.ranges

    @property
    def is_all_ports(self) -> bool:
        return self.ranges == (PortRange(MIN_PORT, MAX_PORT),)

    def contains(self, port: int) -> bool:
        return any(r.contains(port) for r in self.ranges)

    def overlaps(self, other: PortSpec) -> bool:
        if self.is_empty or other.is_empty:
            return self.is_empty and other.is_empty
        return any(a.overlaps(b) for a in self.ranges for b in other.ranges)

    def matching(self, ports: Iterable[int]) -> set[int]:
        """Return the subset of ``ports`` covered by this spec."""

        return {port for port in ports if self.contains(port)}


@dataclass(frozen=True, slots=True)
class AddressIR:
    name: str
    values: tuple[str, ...]
    line: int | None = None


@dataclass(frozen=True, slots=True)
class ServiceIR:
    name: str
    protocol: str
    ports: PortSpec = field(default_factory=PortSpec)
    description: str = ""
    line: int | None = None


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
    line: int | None = None
    location: str = ""


@dataclass(frozen=True, slots=True)
class FirewallIR:
    version: int
    addresses: dict[str, AddressIR]
    services: dict[str, ServiceIR]
    policies: tuple[PolicyIR, ...]
    groups: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source_map: SourceMap = field(default_factory=SourceMap)
