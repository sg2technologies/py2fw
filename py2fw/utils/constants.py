VALID_ACTIONS: frozenset[str] = frozenset({"allow", "deny", "reject"})
VALID_PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp", "icmp", "any"})
ANY_ALIASES: frozenset[str] = frozenset({"any", "0.0.0.0/0", "::/0"})
DATABASE_PORTS: frozenset[int] = frozenset({1433, 1521, 3306, 5432, 6379, 27017})
HIGH_RISK_PORTS: dict[int, str] = {
    22: "Open SSH",
    3389: "Open RDP",
    445: "Open SMB",
}
