import time

from cipher_sec.audit import AuditLog
from cipher_sec.deny_engine import DenyEngine
from cipher_sec.models import Action, ActionRisk, ScopeArtifact
from cipher_sec.runner import SandboxedRunner
from cipher_sec.safety_monitor import SafetyMonitor
from cipher_sec.scope import ScopeAuthorizer


def _env():
    authorizer = ScopeAuthorizer(keys={"client": "kc", "engagement_lead": "kl"})
    deny = DenyEngine()
    audit = AuditLog()
    monitor = SafetyMonitor()
    runner = SandboxedRunner(
        authorizer=authorizer, deny_engine=deny, audit=audit, monitor=monitor,
    )
    now = time.time()
    artifact = ScopeArtifact(
        engagement_id="eng-1",
        client="acme",
        targets=["api.acme.example.com", "*.acme.example.com"],
        technique_allowlist=["recon.passive", "web.sqli", "privesc"],
        technique_denylist=["ddos*"],
        window_start=now - 1,
        window_end=now + 3600,
        operators=["alice"],
    )
    authorizer.sign(artifact, "client")
    authorizer.sign(artifact, "engagement_lead")
    return runner, audit, artifact


def test_benign_action_executes_auto():
    runner, audit, artifact = _env()
    action = Action(
        engagement_id="eng-1", tool="sqlmap", target="api.acme.example.com",
        technique="web.sqli",
    )
    result = runner.run(action, artifact)
    assert result.executed is True
    assert result.decision == "auto"
    assert audit.verify_chain()


def test_out_of_scope_action_denied():
    runner, audit, artifact = _env()
    action = Action(
        engagement_id="eng-1", tool="nmap", target="other.example.com",
        technique="recon.passive",
    )
    result = runner.run(action, artifact)
    assert result.executed is False
    assert result.decision == "deny"
    assert "out-of-scope" in result.output


def test_denylist_technique_refused():
    runner, audit, artifact = _env()
    action = Action(
        engagement_id="eng-1", tool="t", target="api.acme.example.com",
        technique="ddos.syn_flood",
    )
    result = runner.run(action, artifact)
    assert result.executed is False
    assert result.decision == "deny"


def test_destructive_action_requires_approval():
    runner, _audit, artifact = _env()

    reject = lambda a: False
    runner.approval = reject
    action = Action(
        engagement_id="eng-1", tool="meterpreter", target="api.acme.example.com",
        technique="privesc", risk=ActionRisk.DESTRUCTIVE,
    )
    result = runner.run(action, artifact)
    assert result.executed is False
    assert result.decision == "ask_denied"


def test_destructive_action_approved_runs():
    runner, audit, artifact = _env()
    runner.approval = lambda a: True
    action = Action(
        engagement_id="eng-1", tool="meterpreter", target="api.acme.example.com",
        technique="privesc", risk=ActionRisk.DESTRUCTIVE,
    )
    result = runner.run(action, artifact)
    assert result.executed
    assert result.decision == "ask_approved"


def test_safety_monitor_halts_on_credential_pattern():
    runner, _audit, artifact = _env()
    action = Action(
        engagement_id="eng-1", tool="shell", target="api.acme.example.com",
        technique="privesc", risk=ActionRisk.LOW,
        args={"command": "cat ~/.aws/credentials  # aws_access_key_id ="},
    )
    # But deny engine already blocks AWS credential exfil? Let's see — the deny
    # engine has "disable-mfa" + rm -rf + mkfs + dd but not credential read.
    result = runner.run(action, artifact)
    # Either deny engine or safety monitor should catch this
    assert result.executed is False


def test_audit_chain_intact_across_mixed_decisions():
    runner, audit, artifact = _env()
    # One allow, one deny
    a1 = Action(engagement_id="eng-1", tool="x", target="api.acme.example.com",
                technique="web.sqli")
    a2 = Action(engagement_id="eng-1", tool="x", target="api.acme.example.com",
                technique="ddos.syn_flood")
    runner.run(a1, artifact)
    runner.run(a2, artifact)
    assert audit.verify_chain()
