from cipher_sec.recon import ReconLayer


def test_passive_always_allowed():
    ok, reason = ReconLayer().can_run("recon.passive", [])
    assert ok
    assert reason == ""


def test_active_requires_scope_artifact():
    ok, reason = ReconLayer().can_run("recon.active.portscan", [])
    assert not ok
    assert "not in scope" in reason


def test_active_allowed_when_in_scope():
    ok, reason = ReconLayer().can_run(
        "recon.active.portscan", ["recon.active.portscan"]
    )
    assert ok


def test_passive_returns_subdomains():
    result = ReconLayer().run("api.acme.example.com", "recon.passive")
    assert len(result.assets) >= 1
    assert all(a.technique == "recon.passive" for a in result.assets)


def test_portscan_returns_services():
    result = ReconLayer().run("api.acme.example.com", "recon.active.portscan")
    assert len(result.assets) == 3
    assert all(a.kind == "service" for a in result.assets)


def test_deterministic_on_same_input():
    r1 = ReconLayer().run("t.example.com", "recon.passive")
    r2 = ReconLayer().run("t.example.com", "recon.passive")
    assert [a.target for a in r1.assets] == [a.target for a in r2.assets]


def test_unknown_technique_rejected():
    ok, reason = ReconLayer().can_run("recon.active.unknown", [])
    assert not ok
    assert "unknown recon technique" in reason
