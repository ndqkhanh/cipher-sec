"""Append-only, hash-chained audit log. Per-tenant HMAC signing for MVP."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

_GENESIS = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    engagement_id: Optional[str] = None
    scope_artifact_id: Optional[str] = None
    action_id: Optional[str] = None
    principal: str = ""
    approver: Optional[str] = None
    tool: str = ""
    technique: str = ""
    args_hash: str = ""
    decision: str = ""                       # auto | ask_approved | ask_denied | deny
    result_hash: str = ""
    before_snapshot_hash: str = ""
    after_snapshot_hash: str = ""
    prev_entry_hash: str = _GENESIS
    entry_hash: str = ""
    signature: str = ""
    timestamp: float = field(default_factory=time.time)

    def payload(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "entry_id": self.entry_id,
            "engagement_id": self.engagement_id,
            "scope_artifact_id": self.scope_artifact_id,
            "action_id": self.action_id,
            "principal": self.principal,
            "approver": self.approver,
            "tool": self.tool,
            "technique": self.technique,
            "args_hash": self.args_hash,
            "decision": self.decision,
            "result_hash": self.result_hash,
            "before_snapshot_hash": self.before_snapshot_hash,
            "after_snapshot_hash": self.after_snapshot_hash,
            "timestamp": self.timestamp,
            "prev_entry_hash": self.prev_entry_hash,
        }

    def _canonical(self) -> bytes:
        return json.dumps(self.payload(), sort_keys=True, default=str).encode("utf-8")

    def seal(self, signing_key: bytes) -> None:
        h = hashlib.sha256()
        h.update(self.prev_entry_hash.encode("ascii"))
        h.update(b"|")
        h.update(self._canonical())
        self.entry_hash = h.hexdigest()
        self.signature = hmac.new(signing_key, self.entry_hash.encode("ascii"), hashlib.sha256).hexdigest()


@dataclass
class AuditLog:
    """Append-only in-process audit log with hash chain + HMAC signing."""

    signing_key: bytes = b"dev-only-cipher-sec-audit-key"
    _entries: list[AuditEntry] = field(default_factory=list)

    def append(self, entry: AuditEntry) -> AuditEntry:
        entry.seq = len(self._entries) + 1
        entry.prev_entry_hash = (
            self._entries[-1].entry_hash if self._entries else _GENESIS
        )
        entry.seal(self.signing_key)
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def verify_chain(self) -> bool:
        prev = _GENESIS
        for e in self._entries:
            h = hashlib.sha256()
            h.update(prev.encode("ascii"))
            h.update(b"|")
            h.update(e._canonical())
            if h.hexdigest() != e.entry_hash:
                return False
            expected_sig = hmac.new(
                self.signing_key, e.entry_hash.encode("ascii"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, e.signature):
                return False
            prev = e.entry_hash
        return True
