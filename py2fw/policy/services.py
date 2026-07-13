from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    protocol: str
    ports: tuple[int, ...]
    description: str = ""
