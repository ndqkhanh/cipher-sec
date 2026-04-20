"""Hard-deny engine — outranks scope artifacts, bundle approvals, and HITL.

Platform-level rules (non-overridable) + tenant-level rules (additive).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import Action


@dataclass
class DenyRule:
    id: str
    description: str
    # Matches on operation/technique via fnmatch (None = any).
    technique_pattern: Optional[str] = None
    tool_pattern: Optional[str] = None
    # Forbidden argument patterns (regex) applied to any string-ish arg.
    forbidden_arg_regexes: list[re.Pattern[str]] = field(default_factory=list)
    # If `target_not_in_scope_only` is True, the rule fires only when
    # the action's target looks non-scope (the engine defers that to scope).
    platform: bool = True   # if True, cannot be disabled by tenants


@dataclass
class DenyDecision:
    rule_id: Optional[str]
    reason: str


def _platform_rules() -> list[DenyRule]:
    return [
        DenyRule(
            id="platform.no.ransomware",
            description="No ransomware techniques",
            technique_pattern="ransomware*",
        ),
        DenyRule(
            id="platform.no.ddos",
            description="No DDoS techniques",
            technique_pattern="ddos*",
        ),
        DenyRule(
            id="platform.destructive.shell",
            description="Block rm -rf / :(){:|:&};: / mkfs / dd patterns",
            forbidden_arg_regexes=[
                re.compile(r"\brm\s+-rf\b"),
                re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};"),
                re.compile(r"\bmkfs\b"),
                re.compile(r"\bdd\b\s+if=.*\s+of=/dev/"),
            ],
        ),
        DenyRule(
            id="platform.no.idp.modify",
            description="No modifications to identity providers",
            technique_pattern="*.idp.*",
        ),
        DenyRule(
            id="platform.no.mfa.disable",
            description="No MFA disable",
            forbidden_arg_regexes=[
                re.compile(r"\bdisable[-_\s]mfa\b", re.IGNORECASE),
            ],
        ),
    ]


@dataclass
class DenyEngine:
    """Evaluate actions against platform (fixed) + tenant (editable) rules."""

    tenant_rules: list[DenyRule] = field(default_factory=list)
    _platform: list[DenyRule] = field(default_factory=_platform_rules)

    def add_tenant_rule(self, rule: DenyRule) -> None:
        if rule.platform:
            raise ValueError("tenant rules cannot claim platform=True")
        self.tenant_rules.append(rule)

    def evaluate(self, action: Action) -> Optional[DenyDecision]:
        for rule in self._platform + self.tenant_rules:
            if _matches(rule, action):
                return DenyDecision(rule_id=rule.id, reason=rule.description)
        return None


def _matches(rule: DenyRule, action: Action) -> bool:
    if rule.technique_pattern and fnmatch.fnmatchcase(action.technique, rule.technique_pattern):
        return True
    if rule.tool_pattern and fnmatch.fnmatchcase(action.tool, rule.tool_pattern):
        return True
    for rx in rule.forbidden_arg_regexes:
        for v in action.args.values():
            if isinstance(v, str) and rx.search(v):
                return True
    return False
