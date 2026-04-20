# Cipher-Sec — System Design

## Topology

Per-engagement deployment. Each engagement gets its own sandbox (VM / dedicated container), its own audit log, its own scope authorization artifact. The platform provides the orchestration surface but never shares data across engagements.

```
Operator
    │ (auth via SSO + hardware key)
    ▼
┌──────────────┐
│ Gateway      │  — signs scope artifacts; session pinning; rate limiting
└──────┬───────┘
       │
┌──────┴──────────┐
│ Orchestrator    │  ← validates scope artifact on every action
└─┬────────┬──────┘
  │        │
  ▼        ▼
Recon  Exploit Runner (sandbox VM per engagement)
  │        │
  └───┬────┘
      ▼
   Safety Monitor (separate process, different model family)
      │
      ▼
   Append-only Audit Log (hash-chained, signed)

↕ Supply-Chain Defense on LLM egress
↕ Observability → OTel / customer SIEM
```

## Data model

```python
class ScopeArtifact:
    id: UUID
    engagement_id: UUID
    targets: list[CIDR|FQDN|URL]
    technique_allowlist: list[str]   # e.g. "recon.passive", "web.auth-bypass"
    technique_denylist: list[str]
    window: {"starts": datetime, "ends": datetime}
    operators: list[PrincipalID]
    signed_by: list[Signature]        # client + engagement lead

class Engagement:
    id: UUID
    scope: ScopeArtifact
    mode: "attacker" | "defender"
    state: "active" | "paused" | "closed"
    started_at, ended_at

class Action:
    id: UUID
    engagement_id: UUID
    tool: str
    args: dict
    risk: "low" | "medium" | "destructive"
    policy_decision: "auto" | "asked_and_approved" | "asked_and_denied" | "denied"
    result: dict
    before_snapshot_hash: str
    after_snapshot_hash: str
    trace_ref: UUID

class Finding:
    id: UUID
    engagement_id: UUID
    title: str
    cvss: CVSSVector
    reproducible_steps: list[Action.id]
    evidence_refs: list[ChunkRef]
    confirmed: bool                   # cross-channel evidence agrees
```

## Public API

```
POST /v1/engagements                  # create with signed ScopeArtifact
GET  /v1/engagements/{id}
POST /v1/engagements/{id}/pause
POST /v1/engagements/{id}/close

POST /v1/engagements/{id}/actions     # propose an action; returns policy decision
POST /v1/engagements/{id}/actions/{aid}/approve   # HITL approval
POST /v1/engagements/{id}/actions/{aid}/reject

GET  /v1/engagements/{id}/findings
GET  /v1/engagements/{id}/audit       # signed hash-chained entries
GET  /v1/engagements/{id}/report      # final PDF/JSON
```

## Scope artifact signing

Scope artifacts are signed JWS with:
- Client signing key (customer's auth-pinned key).
- Engagement-lead signing key (your org).

Both signatures required. Signature verification happens on every action — if the artifact is missing either, action is refused.

## Deployment

- **Containerized** — one VM per engagement for sandbox isolation.
- **Postgres** — engagement metadata, findings, audit chain index.
- **Object store** — raw trace artifacts, PDF reports.
- **Redis** — per-engagement working state, approval queues.
- **HSM / cloud KMS** — scope-artifact and audit-log signing keys.

## SLOs

| Metric | Target |
|---|---|
| Scope-artifact verification per action | p95 < 10 ms |
| Action → policy decision | p95 < 200 ms |
| HITL approval turnaround (sev1) | p95 < 5 min |
| Safety monitor cadence | every 5 steps, p95 < 3 s |
| Audit entry write-ahead | 100% (mandatory before effect) |
| False-positive sabotage flags @ 1% target FPR | < 10% ideally; measured weekly |

## Failure handling

| Failure | Response |
|---|---|
| Scope artifact expired mid-engagement | All future actions refused; operator must re-sign |
| Sandbox VM compromised (alarm trips) | Engagement paused; forensic snapshot retained; operator paged |
| Safety monitor flags Level 3 | Session paused; credentials revoked; forensic snapshot |
| HITL timeout | No auto-approval; action dropped; operator paged for manual completion |
| LLM provider outage | Failover to secondary; if unavailable, engagement paused |

## Security posture

- **Signed scope artifacts** required for every engagement.
- **Short-lived sandbox credentials** minted just-in-time; TTL < engagement duration.
- **Per-tenant keys for audit log signing**; public keys published for external verification.
- **No secrets in prompts** — credentials injected by the sandbox runner, never via the LLM context.
- **Supply chain** — direct vendor endpoints; transparency log; response anomaly screening per [docs/35](../../docs/35-malicious-intermediary-attacks.md).
- **Hard deny: identity-provider modifications, cross-tenant data movement, off-scope traffic.**

## Scaling

- Per-engagement sandbox isolation means horizontal scaling = more hardware.
- Audit log signing is fast; not a bottleneck.
- Safety monitor is nano-tier; concurrent engagements scale linearly.

## Roadmap (post-v1)

- Learned exploit-path recommender from red-team corpus.
- Cross-engagement (anonymized) pattern library for emerging techniques.
- SOC integration: findings pushed as enriched alerts to the client's SIEM.
- Automated CVE-to-exploit-chain planner with sandbox validation.

## Anti-scope

- No autonomous red-teaming of unknown/unauthorized targets.
- No data exfil / C2 infrastructure (by construction — egress allow-listed to scope).
- No integration with "dark web" data aggregators (legal exposure).
- No replacement for human IR teams.
