VALID_ACTIONS: frozenset[str] = frozenset({"allow", "deny", "reject"})
VALID_PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp", "icmp", "any"})
ANY_ALIASES: frozenset[str] = frozenset({"any", "0.0.0.0/0", "::/0"})

DATABASE_PORTS: frozenset[int] = frozenset({1433, 1521, 3306, 5432, 6379, 9042, 27017})
HIGH_RISK_PORTS: dict[int, str] = {
    21: "Open FTP",
    22: "Open SSH",
    23: "Open Telnet",
    445: "Open SMB",
    3389: "Open RDP",
    5900: "Open VNC",
    5985: "Open WinRM",
    5986: "Open WinRM",
}

# A public prefix at or below this length is treated as an over-broad source.
BROAD_PREFIX_MAX_LEN: dict[int, int] = {4: 16, 6: 48}

# Protocols that carry credentials or data unencrypted, flagged on any allow rule.
CLEARTEXT_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    80: "HTTP",
    161: "SNMP",
}

# A single service spanning more ports than this (but not all) is flagged as overly wide.
WIDE_PORT_RANGE: int = 1024
