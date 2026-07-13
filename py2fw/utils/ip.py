from __future__ import annotations

import ipaddress
import re

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")


def is_any(value: str) -> bool:
    return value.lower() in {"any", "0.0.0.0/0", "::/0"}


def is_valid_ip_or_cidr(value: str) -> bool:
    if is_any(value):
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(HOSTNAME_RE.match(value)) and not is_valid_ip_or_cidr(value)


def is_valid_endpoint(value: str) -> bool:
    return is_valid_ip_or_cidr(value) or is_valid_hostname(value)


def normalize_network(value: str) -> str:
    if is_any(value):
        return "any"
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value.lower()
