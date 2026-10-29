"""Append-only, hash-chained audit log (JSON Lines).

Each entry records the SHA-256 of the previous entry, and its own ``hash`` covers
every other field. Editing, reordering or deleting any line breaks the chain,
which :func:`verify_log` detects. Ship the log to WORM storage or a SIEM for
protection against wholesale replacement.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(entry: dict[str, Any]) -> str:
    body = {key: value for key, value in entry.items() if key != "hash"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def read_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def append_event(path: Path, event: str, actor: str, **details: object) -> dict[str, Any]:
    entries = read_log(path)
    previous = entries[-1] if entries else None
    entry: dict[str, Any] = {
        "seq": (previous["seq"] + 1) if previous else 1,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "event": event,
        "actor": actor,
        **details,
        "prev": previous["hash"] if previous else GENESIS,
    }
    entry["hash"] = _digest(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical(entry) + "\n")
    return entry


@dataclass(frozen=True, slots=True)
class LogVerification:
    entries: int
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_log(path: Path) -> LogVerification:
    try:
        entries = read_log(path)
    except json.JSONDecodeError as exc:
        return LogVerification(0, (f"unreadable entry: {exc}",))
    problems: list[str] = []
    previous_hash = GENESIS
    for index, entry in enumerate(entries, start=1):
        if entry.get("seq") != index:
            problems.append(f"entry {index}: sequence is {entry.get('seq')}, expected {index}")
        if entry.get("prev") != previous_hash:
            problems.append(f"entry {index}: chain broken (prev hash does not match)")
        if entry.get("hash") != _digest(entry):
            problems.append(f"entry {index}: content was modified (hash mismatch)")
        previous_hash = str(entry.get("hash"))
    return LogVerification(len(entries), tuple(problems))
