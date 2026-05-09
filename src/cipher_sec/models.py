"""Cipher-Sec data model — all pydantic."""
from __future__ import annotations

import enum
import time
import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field


class EngagementMode(str, enum.Enum):
    ATTACKER = "attacker"
    DEFENDER = "defender"


class TechniqueClass(str, enum.Enum):
    RECON_PASSIVE = "recon.passive"
    RECON_ACTIVE_PORTSCAN = "recon.active.portscan"
    RECON_ACTIVE_SUBDOMAIN = "recon.active.subdomain"
    WEB_AUTH_FUZZ = "web.auth.fuzz"
    WEB_AUTHZ_BYPASS = "web.authz.bypass"
    WEB_SQLI = "web.sqli"
    WEB_XSS = "web.xss"
    NET_PORTSCAN = "net.portscan"
    PRIVESC = "privesc"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral.movement"
    DATA_EXFIL_SIM = "data.exfil.sim"
    DDOS = "ddos"
    RANSOMWARE = "ransomware"


class ActionRisk(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    DESTRUCTIVE = "destructive"


class ScopeArtifact(BaseModel):
    """Cryptographically signed authorization artifact for an engagement."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    client: str                                      # e.g. acme.example.com
    targets: list[str]                               # CIDR / FQDN globs
    technique_allowlist: list[str]                   # strings matching TechniqueClass values
    technique_denylist: list[str] = Field(default_factory=list)
    window_start: float                              # unix epoch
    window_end: float
    operators: list[str]                             # principal IDs
    max_concurrent_actions: int = 3
    hitl_channel: str = ""
    signatures: dict[str, str] = Field(default_factory=dict)   # principal → hex signature
    issued_at: float = Field(default_factory=time.time)


class Action(BaseModel):
    """A single proposed action against an in-scope target."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    target: str
    technique: str                                   # TechniqueClass value
    risk: ActionRisk = ActionRisk.LOW
    expected_effect: str = ""
    reversibility: str = "reversible"
    dry_run_supported: bool = True


class Finding(BaseModel):
    """A vulnerability / observation found during an engagement."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    engagement_id: str
    title: str
    severity: str = "low"                            # critical | high | medium | low | info
    cvss_base: float = 0.0
    affected_targets: list[str] = Field(default_factory=list)
    reproducible_step_ids: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confirmed: bool = False
    remediation_hint: str = ""
