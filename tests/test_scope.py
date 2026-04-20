import time

import pytest
from cipher_sec.models import Action, ActionRisk, ScopeArtifact
from cipher_sec.scope import ScopeAuthorizer, SignatureError


def _keys():
    return {"client": "k-client", "engagement_lead": "k-lead"}


def _sign_fresh(authorizer: ScopeAuthorizer, **overrides) -> ScopeArtifact:
    now = time.time()
    defaults = dict(
        engagement_id="eng-1",
        client="acme",
        targets=["api.acme.example.com", "10.0.0.0/24"],
        technique_allowlist=["recon.passive", "web.authz.bypass"],
        technique_denylist=["ddos*"],
        window_start=now - 1,
        window_end=now + 3600,
        operators=["alice@pentest"],
    )
    defaults.update(overrides)
    artifact = ScopeArtifact(**defaults)
    authorizer.sign(artifact, "client")
    authorizer.sign(artifact, "engagement_lead")
    return artifact


def test_happy_path_verifies():
    auth = ScopeAuthorizer(keys=_keys())
    artifact = _sign_fresh(auth)
    auth.verify(artifact)   # no raise


def test_missing_required_signature_fails():
    auth = ScopeAuthorizer(keys=_keys())
    now = time.time()
    artifact = ScopeArtifact(
        engagement_id="eng-1", client="acme",
        targets=["t"], technique_allowlist=["*"],
        window_start=now, window_end=now + 3600,
        operators=["alice"],
    )
    auth.sign(artifact, "client")   # missing engagement_lead
    with pytest.raises(SignatureError, match="missing required signatures"):
        auth.verify(artifact)


def test_tampered_field_invalidates():
    auth = ScopeAuthorizer(keys=_keys())
    artifact = _sign_fresh(auth)
    artifact.targets = ["different.example.com"]
    with pytest.raises(SignatureError, match="invalid signature"):
        auth.verify(artifact)


def test_expired_artifact_rejected():
    auth = ScopeAuthorizer(keys=_keys())
    now = time.time()
    artifact = _sign_fresh(
        auth,
        window_start=now - 7200,
        window_end=now - 3600,   # expired
    )
    with pytest.raises(SignatureError, match="expired"):
        auth.verify(artifact)


def test_future_window_rejected():
    auth = ScopeAuthorizer(keys=_keys())
    now = time.time()
    artifact = _sign_fresh(auth, window_start=now + 3600, window_end=now + 7200)
    with pytest.raises(SignatureError, match="not yet valid"):
        auth.verify(artifact)


def test_action_in_scope_technique_allowed():
    artifact = ScopeArtifact(
        engagement_id="eng-1", client="acme",
        targets=["api.acme.example.com"],
        technique_allowlist=["web.authz.bypass"],
        window_start=0, window_end=1,
        operators=["alice"],
    )
    action = Action(
        engagement_id="eng-1", tool="burp", target="api.acme.example.com",
        technique="web.authz.bypass",
    )
    ok, reason = ScopeAuthorizer.action_in_scope(action, artifact)
    assert ok, reason


def test_action_out_of_scope_wrong_engagement():
    artifact = ScopeArtifact(
        engagement_id="eng-1", client="acme", targets=["*"], technique_allowlist=["*"],
        window_start=0, window_end=1, operators=["alice"],
    )
    action = Action(
        engagement_id="eng-2", tool="x", target="t", technique="recon.passive",
    )
    ok, reason = ScopeAuthorizer.action_in_scope(action, artifact)
    assert not ok
    assert "engagement_id mismatch" in reason


def test_action_out_of_scope_wrong_target():
    artifact = ScopeArtifact(
        engagement_id="eng-1", client="acme",
        targets=["api.acme.example.com"], technique_allowlist=["*"],
        window_start=0, window_end=1, operators=["alice"],
    )
    action = Action(
        engagement_id="eng-1", tool="x", target="other.example.com", technique="recon.passive",
    )
    ok, reason = ScopeAuthorizer.action_in_scope(action, artifact)
    assert not ok
    assert "not in scope targets" in reason


def test_action_denied_by_denylist():
    artifact = ScopeArtifact(
        engagement_id="eng-1", client="acme",
        targets=["t"], technique_allowlist=["*"], technique_denylist=["ddos*"],
        window_start=0, window_end=1, operators=["alice"],
    )
    action = Action(
        engagement_id="eng-1", tool="x", target="t", technique="ddos.syn_flood",
    )
    ok, reason = ScopeAuthorizer.action_in_scope(action, artifact)
    assert not ok
    assert "denylist" in reason
