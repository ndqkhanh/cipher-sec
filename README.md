# Cipher-Sec — Security Agent (MVP)

Walking-skeleton implementation of the [Cipher-Sec design](architecture.md). Every action runs through a **cryptographic scope authorization artifact** (HMAC-signed by both client and engagement lead, with a valid time window), then a **platform deny-engine** (non-overridable), then **HITL** on destructive actions, then the **sandboxed runner**, with a **continuous safety monitor** and a **hash-chained + HMAC-signed audit log**.

## What works today

- **`ScopeAuthorizer`** — signs / verifies scope artifacts with HMAC-SHA256. Two signatures required (client + engagement_lead). Action-level scope check (engagement ID, target glob, technique allow/deny lists).
- **`DenyEngine`** — platform rules (ransomware, DDoS, `rm -rf`, `mkfs`, fork bombs, `dd if=*/of=/dev/`, MFA-disable, IdP-modify) + additive tenant rules.
- **`SandboxedRunner`** — composes scope verification → deny engine → HITL → mock execution → safety-monitor → audit write. Every decision recorded.
- **`SafetyMonitor`** — rule-based detector for credential exfil, persistence plants, cross-scope pivots, false-success reports, IdP modifications.
- **`AuditLog`** — append-only, hash-chained, HMAC-signed per entry. Tampering with any field or signature breaks `verify_chain()`.
- **`EngagementStore`** — enforces attacker/defender mutual exclusion per (operator, target).
- **`ReconLayer`** — deterministic mock passive + active recon; active techniques gated by scope.
- **FastAPI** — `POST /v1/engagements`, `POST /v1/actions`, `POST /v1/recon`, `GET /v1/audit`, `GET /healthz` on `:8007`.
- **47 passing tests**.

## Run locally

From **this project folder**:

```bash
make install   # .venv + harness_core + this project editable
make test      # 47 tests, no API keys needed
make run       # http://localhost:8007/docs
```

Example flow:

```bash
# 1. Create engagement with signed scope artifact
ENG=$(curl -sX POST http://localhost:8007/v1/engagements \
  -H 'content-type: application/json' \
  -d '{"engagement_id":"eng-1","client":"acme.example.com",
       "targets":["api.acme.example.com"],
       "technique_allowlist":["recon.passive","web.sqli"],
       "window_hours":1,"operators":["alice"],"mode":"attacker"}' | jq -r .engagement_id)

# 2. Submit an in-scope action
curl -sX POST http://localhost:8007/v1/actions \
  -H 'content-type: application/json' \
  -d "{\"engagement_id\":\"$ENG\",\"tool\":\"sqlmap\",
       \"target\":\"api.acme.example.com\",\"technique\":\"web.sqli\",\"risk\":\"low\"}" | jq

# 3. Passive recon
curl -sX POST "http://localhost:8007/v1/recon?engagement_id=$ENG&target=api.acme.example.com&technique=recon.passive" | jq

# 4. Inspect signed audit log
curl -s "http://localhost:8007/v1/audit?limit=10" | jq
```

## Run via Docker

```bash
make docker-up
curl -s http://localhost:8007/healthz
make docker-down
```

## Python API

```python
import time
from cipher_sec import (
    AuditLog, DenyEngine, ScopeArtifact, ScopeAuthorizer,
    SandboxedRunner, SafetyMonitor,
    Action, ActionRisk,
)

auth = ScopeAuthorizer(keys={"client": "k1", "engagement_lead": "k2"})
artifact = ScopeArtifact(
    engagement_id="eng-1", client="acme",
    targets=["api.acme.example.com"],
    technique_allowlist=["web.sqli"],
    window_start=time.time(), window_end=time.time() + 3600,
    operators=["alice"],
)
auth.sign(artifact, "client")
auth.sign(artifact, "engagement_lead")

runner = SandboxedRunner(
    authorizer=auth, deny_engine=DenyEngine(),
    audit=AuditLog(), monitor=SafetyMonitor(),
)

action = Action(
    engagement_id="eng-1", tool="sqlmap",
    target="api.acme.example.com", technique="web.sqli",
)
result = runner.run(action, artifact)
print(result.decision, result.executed)   # "auto" True
```

## Tests

```bash
make test
```

- [`tests/test_scope.py`](tests/test_scope.py) — HMAC sign/verify, tamper detection, window validation, action scope check.
- [`tests/test_deny_engine.py`](tests/test_deny_engine.py) — platform rules, tenant rule addition, rule matching.
- [`tests/test_audit.py`](tests/test_audit.py) — hash chain integrity, signature tampering.
- [`tests/test_engagements.py`](tests/test_engagements.py) — mutual exclusion per (operator, target), active/close lifecycle.
- [`tests/test_recon.py`](tests/test_recon.py) — passive vs active gating, deterministic output.
- [`tests/test_runner.py`](tests/test_runner.py) — end-to-end decision paths, HITL, safety halt, audit continuity.
- [`tests/test_app.py`](tests/test_app.py) — HTTP endpoints.

## Architecture mapping

| Block | Code |
|---|---|
| [01 Scope authorization](blocks/01-scope-authorization.md) | `cipher_sec.scope.ScopeAuthorizer` + `cipher_sec.models.ScopeArtifact` |
| [02 Recon layer](blocks/02-recon-layer.md) | `cipher_sec.recon.ReconLayer` |
| [03 Sandboxed exploit runner](blocks/03-sandboxed-exploit-runner.md) | `cipher_sec.runner.SandboxedRunner` |
| [04 Policy deny engine](blocks/04-policy-deny-engine.md) | `cipher_sec.deny_engine.DenyEngine` |
| [05 HITL on destructive](blocks/05-hitl-on-destructive.md) | `SandboxedRunner.approval` callback |
| [08 Safety monitor](blocks/08-safety-monitor.md) | `cipher_sec.safety_monitor.SafetyMonitor` |
| [09 Audit log](blocks/09-audit-log.md) | `cipher_sec.audit.AuditLog` (HMAC-signed, hash-chained) |

## Production readiness

- [x] Two-signature scope artifacts; expired / tampered artifacts fail closed
- [x] Non-bypassable platform deny rules
- [x] HITL required for destructive actions
- [x] Hash-chained + signed audit log with tamper detection test
- [x] Attacker/defender mode mutual exclusion
- [x] FastAPI + Dockerfile + healthcheck
- [ ] JWS / Ed25519 signatures instead of HMAC (v0.2)
- [ ] Real sandboxed exec (containers + scoped creds); MVP uses mock executor
- [ ] Supply-chain defense layer (transparency log, response-anomaly screener)
- [ ] LaStraj red-team corpus + nano-tier LLM monitor

## License

MIT
