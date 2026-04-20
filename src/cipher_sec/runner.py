"""SandboxedRunner — mock execution path with scope verification + HITL hook."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Optional

from .audit import AuditEntry, AuditLog
from .deny_engine import DenyEngine
from .models import Action, ActionRisk, ScopeArtifact
from .safety_monitor import SafetyMonitor, SafetyVerdict
from .scope import ScopeAuthorizer, SignatureError

ApprovalFn = Callable[[Action], bool]


def _auto_approve(_action: Action) -> bool:
    return True


def _default_mock_executor(action: Action) -> str:
    return f"mock-result:{action.tool}({sorted(action.args.items())})"


def _hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class RunnerResult:
    action_id: str
    decision: str                           # auto | ask_approved | ask_denied | deny | safety_halt
    executed: bool
    output: str = ""
    safety_verdict: Optional[SafetyVerdict] = None


@dataclass
class SandboxedRunner:
    """Compose scope-check, deny-engine, HITL, mock-exec, safety-monitor, audit."""

    authorizer: ScopeAuthorizer
    deny_engine: DenyEngine
    audit: AuditLog
    monitor: SafetyMonitor
    approval: ApprovalFn = _auto_approve
    _mock_executor: Callable[[Action], str] = _default_mock_executor

    def run(
        self,
        action: Action,
        artifact: ScopeArtifact,
        *,
        principal: str = "operator",
    ) -> RunnerResult:
        # 1. Scope artifact signature + window verification
        try:
            self.authorizer.verify(artifact)
        except SignatureError as e:
            self._record(action, artifact, principal, "deny", f"scope invalid: {e}")
            return RunnerResult(action_id=action.id, decision="deny", executed=False,
                                output=f"scope invalid: {e}")

        # 2. Action in scope?
        ok, reason = self.authorizer.action_in_scope(action, artifact)
        if not ok:
            self._record(action, artifact, principal, "deny", f"out-of-scope: {reason}")
            return RunnerResult(action_id=action.id, decision="deny", executed=False,
                                output=f"out-of-scope: {reason}")

        # 3. Hard-deny engine
        deny = self.deny_engine.evaluate(action)
        if deny is not None:
            self._record(action, artifact, principal, "deny", f"deny rule {deny.rule_id}: {deny.reason}")
            return RunnerResult(action_id=action.id, decision="deny", executed=False,
                                output=f"hard deny: {deny.rule_id}")

        # 4. HITL on destructive actions
        decision = "auto"
        approver: Optional[str] = None
        if action.risk == ActionRisk.DESTRUCTIVE:
            if not self.approval(action):
                self._record(action, artifact, principal, "ask_denied", "human rejected")
                return RunnerResult(action_id=action.id, decision="ask_denied", executed=False,
                                    output="human rejected")
            decision = "ask_approved"
            approver = "human-approver"

        # 5. Execute (mock)
        action_blob = json.dumps({"tool": action.tool, "args": action.args}, sort_keys=True, default=str)
        safety = self.monitor.evaluate_action_text(action_blob)
        if safety.level >= 3:
            self._record(action, artifact, principal, "deny", f"safety halt: {safety.classes}")
            return RunnerResult(action_id=action.id, decision="safety_halt", executed=False,
                                output=f"safety halt: {safety.classes}",
                                safety_verdict=safety)

        executor = self._mock_executor
        output = executor(action) if callable(executor) else f"mock:{action.tool}"
        self._record(action, artifact, principal, decision, "executed", approver=approver, output=output)
        return RunnerResult(
            action_id=action.id,
            decision=decision,
            executed=True,
            output=output,
            safety_verdict=safety,
        )

    def _record(
        self,
        action: Action,
        artifact: ScopeArtifact,
        principal: str,
        decision: str,
        note: str,
        *,
        approver: Optional[str] = None,
        output: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            seq=0,
            engagement_id=action.engagement_id,
            scope_artifact_id=artifact.id,
            action_id=action.id,
            principal=principal,
            approver=approver,
            tool=action.tool,
            technique=action.technique,
            args_hash=_hash(json.dumps(action.args, sort_keys=True, default=str)),
            decision=decision,
            result_hash=_hash(output or note),
        )
        return self.audit.append(entry)
