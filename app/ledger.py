"""Append-only evidence log: JSONL with a SHA-256 hash chain.

Each entry stores the hash of the previous entry, so any later edit, deletion or
reordering of past entries is detected by verify().
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(body)).encode("utf-8")).hexdigest()


def anonymise(value: str, salt: str) -> str:
    """Pseudonymous reference for a recipient: salted hash plus the domain only."""
    local, _, domain = value.partition("@")
    digest = hashlib.sha256((salt + value.lower()).encode("utf-8")).hexdigest()[:16]
    return f"{digest}@{domain.lower()}"


class Ledger:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.touch()

    def _read_all(self) -> list[dict]:
        entries = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def append(self, incident_id: str, event: str, payload: dict, ts: datetime | None = None) -> dict:
        with self._lock:
            entries = self._read_all()
            prev = entries[-1]["hash"] if entries else GENESIS
            body = {
                "seq": len(entries) + 1,
                "ts": (ts or datetime.now(timezone.utc)).isoformat(),
                "incident_id": incident_id,
                "event": event,
                "payload": payload,
            }
            entry = dict(body)
            entry["prev_hash"] = prev
            entry["hash"] = entry_hash(prev, body)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def entries(self, incident_id: str | None = None) -> list[dict]:
        rows = self._read_all()
        if incident_id is not None:
            rows = [r for r in rows if r["incident_id"] == incident_id]
        return rows

    def verify(self) -> dict:
        """Recompute the whole chain. Returns {ok, count, broken_at, reason}."""
        try:
            rows = self._read_all()
        except (json.JSONDecodeError, OSError) as exc:
            return {"ok": False, "count": 0, "broken_at": 1, "reason": f"unreadable ledger: {exc}"}
        prev = GENESIS
        for i, row in enumerate(rows, start=1):
            body = {k: row.get(k) for k in ("seq", "ts", "incident_id", "event", "payload")}
            if row.get("seq") != i:
                return {"ok": False, "count": len(rows), "broken_at": i, "reason": "sequence gap or reorder"}
            if row.get("prev_hash") != prev:
                return {"ok": False, "count": len(rows), "broken_at": i, "reason": "prev_hash mismatch"}
            if entry_hash(prev, body) != row.get("hash"):
                return {"ok": False, "count": len(rows), "broken_at": i, "reason": "entry content altered"}
            prev = row["hash"]
        return {"ok": True, "count": len(rows), "broken_at": None, "reason": ""}
