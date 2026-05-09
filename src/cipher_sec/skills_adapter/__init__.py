"""Cipher-Sec skills adapter — dual stream (analyst prefs + technique discovery).

Dialogue stream (AutoSkill) captures analyst preferences inside a per-analyst
namespace; the failure stream (EvoSkill) distils CTF-style technique skills
from engagement-completion events. The exfil-gate runs at extraction time
so credentials and scope artefacts cannot leak into the SkillBank.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from harness_skills import SkillRecord
from harness_skills.extract import DialogueExtractor, ExtractionContext, FailureExtractor
from harness_skills.extract.failure import FailureTrace
from harness_skills.store import SkillBank

_EXFIL_RE = re.compile(
    r"(?i)(api[_-]?key|secret|hmac|bearer\s+\S+|password\s*[:=]|aws_(?:access|secret)|"
    r"-----BEGIN\s+[A-Z ]+PRIVATE KEY-----)"
)


def exfil_gate(text: str) -> bool:
    """Return True iff the text is safe to store (no credentials / keys)."""
    return _EXFIL_RE.search(text or "") is None


@dataclass
class CipherAnalystPrefExtractor:
    extractor: DialogueExtractor

    @classmethod
    def default(cls) -> CipherAnalystPrefExtractor:
        return cls(extractor=DialogueExtractor(family="extractor-cipher"))

    def from_session(self, turns: list[dict], *, analyst_id: str, session_id: str) -> list[SkillRecord]:
        records = self.extractor.extract(
            turns,
            context=ExtractionContext(session_id=session_id, user_id=analyst_id),
        )
        return [r for r in records if exfil_gate(r.skill.prompt)]


@dataclass
class CipherTechniqueExtractor:
    extractor: FailureExtractor

    @classmethod
    def default(cls) -> CipherTechniqueExtractor:
        return cls(extractor=FailureExtractor(family="extractor-cipher"))

    def from_engagement(self, *, engagement_id: str, traces: list[dict]) -> list[SkillRecord]:
        coerced = [
            FailureTrace(
                task_id=engagement_id,
                task_description=str(t.get("technique", "")),
                failed_output=str(t.get("output", "")),
                diagnostic=str(t.get("diagnostic", "")),
            )
            for t in traces
        ]
        out = self.extractor.extract(coerced, context=ExtractionContext(session_id=engagement_id))
        return [r for r in out if exfil_gate(r.skill.prompt)]


@dataclass
class CipherSkillBank:
    bank: SkillBank

    @classmethod
    def for_engagement(cls, root: Path | str, engagement_id: str) -> CipherSkillBank:
        return cls(bank=SkillBank(root=root, namespace=f"engagements/{engagement_id}"))

    @classmethod
    def for_analyst(cls, root: Path | str, analyst_id: str) -> CipherSkillBank:
        return cls(bank=SkillBank(root=root, namespace=f"analysts/{analyst_id}"))


__all__ = [
    "CipherAnalystPrefExtractor",
    "CipherSkillBank",
    "CipherTechniqueExtractor",
    "exfil_gate",
]
