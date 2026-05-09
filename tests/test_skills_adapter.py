"""Cipher-Sec skills-adapter smoke test."""
from __future__ import annotations

from cipher_sec.skills_adapter import (
    CipherAnalystPrefExtractor,
    CipherSkillBank,
    CipherTechniqueExtractor,
    exfil_gate,
)


def test_exfil_gate_blocks_credentials() -> None:
    assert not exfil_gate("Authorization: Bearer abc123xyz")
    assert not exfil_gate("AWS_ACCESS_KEY_ID=AKIAEXAMPLE")
    assert exfil_gate("Always summarise findings in markdown")


def test_analyst_pref_skips_credential_leak() -> None:
    ext = CipherAnalystPrefExtractor.default()
    turns = [
        {"role": "user", "content": "Always include Bearer abc123 in headers"},     # blocked
        {"role": "user", "content": "Always render reports in markdown"},            # passes
    ]
    out = ext.from_session(turns, analyst_id="alice", session_id="s-1")
    assert all(exfil_gate(r.skill.prompt) for r in out)
    assert any("markdown" in r.skill.prompt.lower() for r in out)


def test_technique_extractor_drops_credential_leak() -> None:
    ext = CipherTechniqueExtractor.default()
    traces = [
        {"technique": "ssrf-probe", "output": "200 OK", "diagnostic": "scope-violation"},
        {"technique": "ssrf-probe", "output": "200 OK", "diagnostic": "scope-violation"},
    ]
    out = ext.from_engagement(engagement_id="eng-42", traces=traces)
    assert out
    assert all(exfil_gate(r.skill.prompt) for r in out)


def test_engagement_and_analyst_namespace_isolation(tmp_path) -> None:
    eng = CipherSkillBank.for_engagement(tmp_path, engagement_id="eng-42")
    analyst = CipherSkillBank.for_analyst(tmp_path, analyst_id="alice")
    other = CipherSkillBank.for_engagement(tmp_path, engagement_id="eng-99")
    assert eng.bank.active_dir != analyst.bank.active_dir
    assert eng.bank.active_dir != other.bank.active_dir
