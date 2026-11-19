"""Tamper-evident audit log: each entry includes the SHA-256 of the previous one."""
from __future__ import annotations

import hashlib
import json
import time


class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []

    def append(self, event: dict) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        body = {"ts": time.time(), "prev": prev, **event}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        self.entries.append(body)
        return body

    def verify(self) -> bool:
        prev = "0" * 64
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True
