"""Optional, reproducible hostname resolution for policy objects.

Hostnames in a policy are passed through literally unless compilation is run
with host resolution enabled. When enabled, names are resolved via DNS once and
pinned in a ``<policy>.py2fw-lock.json`` file so later compiles are deterministic.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from py2fw.parser.schema import PolicyDocument
from py2fw.utils.ip import is_hostname

Resolver = Callable[[str], list[str]]


@dataclass(frozen=True, slots=True)
class HostResolution:
    mapping: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unresolved: tuple[str, ...] = ()
    lockfile: Path | None = None


def collect_hostnames(document: PolicyDocument) -> set[str]:
    return {
        value.lower()
        for values in document.objects.values()
        for value in values
        if is_hostname(value)
    }


def _dns_lookup(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses: set[str] = set()
    for info in infos:
        ip = info[4][0]
        prefix = 128 if ipaddress.ip_address(ip).version == 6 else 32
        addresses.add(f"{ip}/{prefix}")
    return sorted(addresses)


def _lock_path(policy_path: Path) -> Path:
    return policy_path.with_name(policy_path.stem + ".py2fw-lock.json")


def _load_lock(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    hosts = raw.get("hosts", {})
    return {name: list(entry.get("addresses", [])) for name, entry in hosts.items()}


def _write_lock(path: Path, resolved: dict[str, list[str]]) -> None:
    now = datetime.now(UTC).isoformat()
    payload = {
        "version": 1,
        "hosts": {
            name: {"addresses": addresses, "resolved_at": now}
            for name, addresses in sorted(resolved.items())
        },
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def resolve_document_hosts(
    document: PolicyDocument,
    policy_path: Path,
    *,
    do_dns: bool = False,
    refresh: bool = False,
    resolver: Resolver | None = None,
) -> HostResolution:
    hostnames = collect_hostnames(document)
    if not hostnames:
        return HostResolution()

    lock_path = _lock_path(policy_path)
    locked = _load_lock(lock_path)
    lookup = resolver or _dns_lookup

    if do_dns:
        changed = False
        for host in sorted(hostnames):
            if host in locked and not refresh:
                continue
            try:
                locked[host] = lookup(host)
                changed = True
            except OSError:
                continue
        if changed:
            _write_lock(lock_path, {h: locked[h] for h in locked if h in hostnames})

    mapping = {host: tuple(locked[host]) for host in hostnames if locked.get(host)}
    unresolved = tuple(sorted(hostnames - mapping.keys()))
    return HostResolution(mapping=mapping, unresolved=unresolved, lockfile=lock_path)
