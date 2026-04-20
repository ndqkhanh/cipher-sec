import pytest
from cipher_sec.engagements import EngagementStore
from cipher_sec.models import EngagementMode, ScopeArtifact


def _artifact(eng_id: str, op: str = "alice", target: str = "api.acme") -> ScopeArtifact:
    return ScopeArtifact(
        engagement_id=eng_id,
        client="acme",
        targets=[target],
        technique_allowlist=["*"],
        window_start=0,
        window_end=1,
        operators=[op],
    )


def test_create_engagement():
    store = EngagementStore()
    eng = store.create(_artifact("eng-1"), EngagementMode.ATTACKER)
    assert eng.id == "eng-1"
    assert eng.mode == EngagementMode.ATTACKER


def test_mode_mutual_exclusion_same_operator_target():
    store = EngagementStore()
    store.create(_artifact("eng-1"), EngagementMode.ATTACKER)
    with pytest.raises(ValueError, match="attacker engagement"):
        store.create(_artifact("eng-2"), EngagementMode.DEFENDER)


def test_mode_exclusion_relaxed_on_different_operator():
    store = EngagementStore()
    store.create(_artifact("eng-1", op="alice"), EngagementMode.ATTACKER)
    # Different operator → allowed
    store.create(_artifact("eng-2", op="bob"), EngagementMode.DEFENDER)


def test_mode_exclusion_relaxed_on_different_target():
    store = EngagementStore()
    store.create(_artifact("eng-1", target="api.acme"), EngagementMode.ATTACKER)
    store.create(_artifact("eng-2", target="api.other"), EngagementMode.DEFENDER)


def test_close_releases_mutual_exclusion():
    store = EngagementStore()
    store.create(_artifact("eng-1"), EngagementMode.ATTACKER)
    store.close("eng-1")
    # Now defender on same target is allowed
    store.create(_artifact("eng-2"), EngagementMode.DEFENDER)


def test_active_filters_closed():
    store = EngagementStore()
    store.create(_artifact("eng-1"), EngagementMode.ATTACKER)
    store.create(_artifact("eng-2", op="bob"), EngagementMode.ATTACKER)
    store.close("eng-1")
    assert [e.id for e in store.active()] == ["eng-2"]
