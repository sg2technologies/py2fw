from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    source: tuple[str, ...]
    destination: tuple[str, ...]
    services: tuple[str, ...]
    action: str
    enabled: bool = True
    description: str = ""
