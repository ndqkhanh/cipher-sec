from cipher_sec.app import app
from fastapi.testclient import TestClient

client = TestClient(app)


def _create_engagement(eid: str = "eng-test-1"):
    return client.post(
        "/v1/engagements",
        json={
            "engagement_id": eid,
            "client": "acme.example.com",
            "targets": ["api.acme.example.com"],
            "technique_allowlist": ["recon.passive", "web.sqli"],
            "window_hours": 1,
            "operators": ["alice"],
            "mode": "attacker",
        },
    )


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["service"] == "cipher-sec"


def test_create_engagement_signs_artifact():
    r = _create_engagement("eng-a")
    assert r.status_code == 200
    body = r.json()
    assert body["engagement_id"] == "eng-a"
    assert set(body["signed_by"]) == {"client", "engagement_lead"}


def test_submit_action_in_scope_executes():
    _create_engagement("eng-b")
    r = client.post("/v1/actions", json={
        "engagement_id": "eng-b",
        "tool": "sqlmap",
        "target": "api.acme.example.com",
        "technique": "web.sqli",
        "risk": "low",
    })
    assert r.status_code == 200
    assert r.json()["executed"] is True
    assert r.json()["decision"] == "auto"


def test_submit_action_out_of_scope_refused():
    _create_engagement("eng-c")
    r = client.post("/v1/actions", json={
        "engagement_id": "eng-c",
        "tool": "sqlmap",
        "target": "unknown.example.com",
        "technique": "web.sqli",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "deny"
    assert "out-of-scope" in body["output"]


def test_recon_passive_default():
    _create_engagement("eng-d")
    r = client.post("/v1/recon?engagement_id=eng-d&target=api.acme.example.com&technique=recon.passive")
    assert r.status_code == 200
    assert r.json()["assets"]


def test_audit_endpoint_after_actions():
    _create_engagement("eng-e")
    client.post("/v1/actions", json={
        "engagement_id": "eng-e",
        "tool": "sqlmap",
        "target": "api.acme.example.com",
        "technique": "web.sqli",
    })
    r = client.get("/v1/audit?limit=5")
    assert r.status_code == 200
    body = r.json()
    assert body["chain_intact"] is True
    assert body["count"] >= 1
