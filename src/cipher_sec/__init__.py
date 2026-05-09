"""Cipher-Sec: security-engineering agent with scope-authorization artifacts,
HITL-gated destructive actions, and hash-chained audit log."""
from __future__ import annotations

from .audit import AuditEntry, AuditLog
from .deny_engine import DenyEngine, DenyRule
from .engagements import Engagement, EngagementStore
from .models import (
    Action,
    ActionRisk,
    EngagementMode,
    Finding,
    ScopeArtifact,
    TechniqueClass,
)
from .recon import ReconLayer
from .runner import SandboxedRunner, RunnerResult
from .safety_monitor import SafetyMonitor, SafetyVerdict
from .scope import ScopeAuthorizer, SignatureError

__all__ = [
    "Action",
    "ActionRisk",
    "AuditEntry",
    "AuditLog",
    "DenyEngine",
    "DenyRule",
    "Engagement",
    "EngagementMode",
    "EngagementStore",
    "Finding",
    "ReconLayer",
    "RunnerResult",
    "SafetyMonitor",
    "SafetyVerdict",
    "SandboxedRunner",
    "ScopeArtifact",
    "ScopeAuthorizer",
    "SignatureError",
    "TechniqueClass",
]
