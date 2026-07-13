from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AddressGroup:
    name: str
    members: tuple[str, ...]
