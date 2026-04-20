import pytest
from cipher_sec.deny_engine import DenyEngine, DenyRule
from cipher_sec.models import Action


def _action(**over):
    return Action(
        engagement_id="e",
        tool=over.pop("tool", "bash"),
        target=over.pop("target", "t"),
        technique=over.pop("technique", "web.sqli"),
        args=over.pop("args", {}),
    )


def test_ddos_technique_denied_by_platform():
    eng = DenyEngine()
    d = eng.evaluate(_action(technique="ddos.syn_flood"))
    assert d is not None
    assert d.rule_id == "platform.no.ddos"


def test_ransomware_technique_denied():
    eng = DenyEngine()
    d = eng.evaluate(_action(technique="ransomware.encrypt"))
    assert d is not None
    assert d.rule_id == "platform.no.ransomware"


def test_rm_rf_in_args_denied():
    eng = DenyEngine()
    d = eng.evaluate(_action(args={"command": "ls && rm -rf /tmp"}))
    assert d is not None
    assert d.rule_id == "platform.destructive.shell"


def test_mfa_disable_in_args_denied():
    eng = DenyEngine()
    d = eng.evaluate(_action(args={"action": "disable-mfa user=root"}))
    assert d is not None
    assert d.rule_id == "platform.no.mfa.disable"


def test_benign_action_allowed():
    eng = DenyEngine()
    assert eng.evaluate(_action(technique="web.sqli", args={"url": "https://x/y"})) is None


def test_tenant_rules_cannot_claim_platform():
    eng = DenyEngine()
    with pytest.raises(ValueError, match="platform=True"):
        eng.add_tenant_rule(DenyRule(id="t.x", description="x", platform=True))


def test_tenant_rule_added_applies():
    eng = DenyEngine()
    eng.add_tenant_rule(
        DenyRule(id="tenant.no.sqli", description="no sql injection here",
                 technique_pattern="web.sqli", platform=False)
    )
    d = eng.evaluate(_action(technique="web.sqli"))
    assert d is not None
    assert d.rule_id == "tenant.no.sqli"
