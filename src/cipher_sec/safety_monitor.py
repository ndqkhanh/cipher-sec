"""Continuous safety monitor — rule-based for MVP; production swaps in a nano-tier LLM.

Scans the recent action/result trace slice for covert or off-task behavior.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .audit import AuditEntry


@dataclass
class SafetyVerdict:
    level: int                         # 0 clean | 1 soft | 2 medium | 3 hard
    classes: list[str]
    evidence: str = ""
    reason: str = ""


_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "credential_exfil": [
        re.compile(r"aws_access_key_id\s*=", re.IGNORECASE),
        re.compile(r"BEGIN (RSA|OPENSSH) PRIVATE KEY"),
        re.compile(r"\bexport\s+AWS_SECRET", re.IGNORECASE),
    ],
    "persistence_plant": [
        re.compile(r"/etc/systemd/system/", re.IGNORECASE),
        re.compile(r"authorized_keys"),
        re.compile(r"crontab\s+-e"),
    ],
    "cross_scope_pivot": [
        re.compile(r"\battack[-_ ]adjacent\b", re.IGNORECASE),
    ],
    "false_success_report": [
        re.compile(r"\bstatus:\s*success\b.*\berror\b", re.IGNORECASE | re.DOTALL),
    ],
    "idp_modify": [
        re.compile(r"iam[-_]create[-_]user", re.IGNORECASE),
        re.compile(r"disable[-_\s]mfa", re.IGNORECASE),
    ],
}


class SafetyMonitor:
    """Rule-based monitor producing a verdict from recent audit entries."""

    def evaluate(self, recent: list[AuditEntry]) -> SafetyVerdict:
        for entry in recent:
            text = f"{entry.tool} {entry.technique} {entry.args_hash} {entry.result_hash}"
            # In MVP the hashes shield content; real monitor would read raw output.
            for cls, patterns in _PATTERNS.items():
                for rx in patterns:
                    if rx.search(text):
                        return SafetyVerdict(
                            level=3,
                            classes=[cls],
                            evidence=entry.entry_id,
                            reason=f"pattern match: {cls}",
                        )
        return SafetyVerdict(level=0, classes=[])

    def evaluate_action_text(self, action_blob: str) -> SafetyVerdict:
        """Alt entry-point scanning a serialized action payload (for tests)."""
        flagged: list[str] = []
        for cls, patterns in _PATTERNS.items():
            for rx in patterns:
                if rx.search(action_blob):
                    flagged.append(cls)
                    break
        level = 3 if flagged else 0
        return SafetyVerdict(
            level=level,
            classes=flagged,
            reason="pattern match" if flagged else "",
        )
