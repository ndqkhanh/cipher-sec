"""Engagement records + in-memory store. Production persists to Postgres."""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .models import EngagementMode, ScopeArtifact


class EngagementState(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"


@dataclass
class Engagement:
    id: str
    scope: ScopeArtifact
    mode: EngagementMode
    state: EngagementState = EngagementState.ACTIVE
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None


@dataclass
class EngagementStore:
    """In-memory per-engagement registry. Enforces attacker/defender mutual exclusion."""

    _by_id: dict[str, Engagement] = field(default_factory=dict)
    # map of (operator, target-first) -> mode currently engaged, for mutual exclusion
    _operator_target_mode: dict[tuple[str, str], EngagementMode] = field(default_factory=dict)

    def create(self, scope: ScopeArtifact, mode: EngagementMode) -> Engagement:
        # Check attacker/defender mutual exclusion per (operator, target-root)
        if scope.operators and scope.targets:
            op = scope.operators[0]
            tgt = scope.targets[0]
            existing = self._operator_target_mode.get((op, tgt))
            if existing is not None and existing != mode:
                raise ValueError(
                    f"operator {op!r} already has an active {existing.value} engagement on target {tgt!r}"
                )
            self._operator_target_mode[(op, tgt)] = mode

        eng = Engagement(id=scope.engagement_id or uuid.uuid4().hex[:12], scope=scope, mode=mode)
        self._by_id[eng.id] = eng
        return eng

    def get(self, engagement_id: str) -> Optional[Engagement]:
        return self._by_id.get(engagement_id)

    def close(self, engagement_id: str) -> None:
        eng = self._by_id[engagement_id]
        eng.state = EngagementState.CLOSED
        eng.ended_at = time.time()
        if eng.scope.operators and eng.scope.targets:
            self._operator_target_mode.pop(
                (eng.scope.operators[0], eng.scope.targets[0]), None
            )

    def all(self) -> list[Engagement]:
        return list(self._by_id.values())

    def active(self) -> list[Engagement]:
        return [e for e in self._by_id.values() if e.state == EngagementState.ACTIVE]
