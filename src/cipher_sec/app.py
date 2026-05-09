"""FastAPI surface for Cipher-Sec."""
from __future__ import annotations

import time
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import AuditLog
from .deny_engine import DenyEngine
from .engagements import EngagementStore
from .models import Action, ActionRisk, EngagementMode, ScopeArtifact
from .recon import ReconLayer
from .runner import SandboxedRunner
from .safety_monitor import SafetyMonitor
from .scope import ScopeAuthorizer

app = FastAPI(
    title="Cipher-Sec",
    description="Security agent: scope-authorized, HITL-gated, audit-chained.",
    version="0.1.0",
)

_KEYS = {"client": "dev-client-key", "engagement_lead": "dev-lead-key"}
_authorizer = ScopeAuthorizer(keys=_KEYS)
_deny = DenyEngine()
_audit = AuditLog()
_monitor = SafetyMonitor()
_runner = SandboxedRunner(
    authorizer=_authorizer,
    deny_engine=_deny,
    audit=_audit,
    monitor=_monitor,
)
_store = EngagementStore()
_recon = ReconLayer()


class ScopeArtifactReq(BaseModel):
    engagement_id: str
    client: str
    targets: list[str]
    technique_allowlist: list[str]
    technique_denylist: list[str] = Field(default_factory=list)
    window_hours: int = Field(default=24, ge=1, le=720)
    operators: list[str]
    mode: str = "attacker"


class ActionReq(BaseModel):
    engagement_id: str
    tool: str
    target: str
    technique: str
    risk: str = "low"
    args: dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "cipher-sec"}


@app.post("/v1/engagements")
def create_engagement(req: ScopeArtifactReq) -> dict:
    now = time.time()
    artifact = ScopeArtifact(
        engagement_id=req.engagement_id,
        client=req.client,
        targets=req.targets,
        technique_allowlist=req.technique_allowlist,
        technique_denylist=req.technique_denylist,
        window_start=now,
        window_end=now + req.window_hours * 3600,
        operators=req.operators,
    )
    _authorizer.sign(artifact, "client")
    _authorizer.sign(artifact, "engagement_lead")

    try:
        mode = EngagementMode(req.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid mode {req.mode!r}") from e

    try:
        eng = _store.create(artifact, mode)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e

    return {
        "engagement_id": eng.id,
        "scope_artifact_id": artifact.id,
        "signed_by": sorted(artifact.signatures.keys()),
        "mode": mode.value,
    }


@app.post("/v1/actions")
def submit_action(req: ActionReq) -> dict:
    eng = _store.get(req.engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="no such engagement")

    try:
        risk = ActionRisk(req.risk)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"invalid risk {req.risk!r}") from e

    action = Action(
        engagement_id=req.engagement_id,
        tool=req.tool,
        target=req.target,
        technique=req.technique,
        risk=risk,
        args=req.args,
    )
    result = _runner.run(action, eng.scope)
    return {
        "action_id": action.id,
        "decision": result.decision,
        "executed": result.executed,
        "output": result.output[:500],
        "safety_level": result.safety_verdict.level if result.safety_verdict else 0,
    }


@app.post("/v1/recon")
def recon(engagement_id: str, target: str, technique: str = "recon.passive") -> dict:
    eng = _store.get(engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="no such engagement")
    ok, reason = _recon.can_run(technique, eng.scope.technique_allowlist)
    if not ok:
        raise HTTPException(status_code=403, detail=reason)
    result = _recon.run(target, technique)
    return {
        "assets": [{"kind": a.kind, "target": a.target, "evidence": a.evidence} for a in result.assets],
        "notes": result.notes,
    }


@app.get("/v1/audit")
def get_audit(limit: int = 100) -> dict:
    entries = _audit.entries()[-limit:]
    return {
        "count": len(entries),
        "chain_intact": _audit.verify_chain(),
        "entries": [
            {
                "seq": e.seq,
                "engagement_id": e.engagement_id,
                "action_id": e.action_id,
                "tool": e.tool,
                "technique": e.technique,
                "decision": e.decision,
                "entry_hash": e.entry_hash[:16],
                "signature": e.signature[:16],
            }
            for e in entries
        ],
    }
