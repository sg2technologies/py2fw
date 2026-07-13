from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from py2fw.utils.constants import VALID_ACTIONS, VALID_PROTOCOLS


class ServiceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str
    port: int | str | list[int] | None = None
    description: str = ""

    @field_validator("protocol")
    @classmethod
    def protocol_is_supported(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in VALID_PROTOCOLS:
            raise ValueError(f"unsupported protocol: {value}")
        return normalized

    @model_validator(mode="after")
    def port_matches_protocol(self) -> ServiceModel:
        if self.protocol == "icmp":
            return self
        if self.protocol == "any":
            return self
        if self.port is None:
            raise ValueError("tcp and udp services require a port")
        return self


class RuleModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    source: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    action: str
    enabled: bool = True
    description: str = ""

    @field_validator("action")
    @classmethod
    def action_is_supported(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in VALID_ACTIONS:
            raise ValueError(f"unsupported action: {value}")
        return normalized


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    objects: dict[str, list[str]] = Field(default_factory=dict)
    groups: dict[str, list[str]] = Field(default_factory=dict)
    services: dict[str, ServiceModel] = Field(default_factory=dict)
    policies: list[RuleModel] = Field(default_factory=list)

    @field_validator("objects", "groups", "services")
    @classmethod
    def names_are_not_empty(cls, value: dict[str, Any]) -> dict[str, Any]:
        for name in value:
            if not name.strip():
                raise ValueError("names cannot be empty")
        return value
