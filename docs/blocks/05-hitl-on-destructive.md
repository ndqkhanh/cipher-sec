# Cipher-Sec Block 05 — HITL on Destructive Actions

## Responsibility

Every destructive action (privilege escalation, persistence, credential dump, data exfil, lateral movement) queues to a human approver with enough structured context to decide. No destructive action auto-runs.

Reference: [docs/23 human-in-the-loop](../../../docs/23-human-in-the-loop.md).

## Classification

Tool wrappers declare `risk: "destructive"` for any action that:
- Writes to authentication / identity systems.
- Modifies data outside a test/temporary namespace.
- Plants artifacts (files, binaries, scheduled tasks, cron) that outlive the engagement.
- Acquires elevated privileges (root, Domain Admin, cloud-admin).
- Performs data retrieval beyond metadata (credential dump, PII extraction for PoC).

## Approval proposal schema

Every destructive action sent to the approver includes:

```json
{
  "engagement_id": "...",
  "action_id": "...",
  "tool": "metasploit",
  "module": "exploit/linux/http/...",
  "target": "203.0.113.5:8080",
  "scope_artifact_match": true,
  "effect_summary": "Opens reverse shell from target; proves RCE",
  "reversibility": "reversible if shell closed before persistence steps",
  "blast_radius": "single host; no persistence without separate approval",
  "dry_run_result": "vulnerable module; target responds as expected",
  "alternatives": [
    "confirm via blind time-based sqli only (lower PoC value, zero code exec)"
  ],
  "required_approvers": 1,
  "timeout_s": 900
}
```

## Channels

- **Slack / Teams** — primary. Interactive card with Approve / Reject / Ask for Info.
- **Cipher-Sec UI** — full trace drill-down for deeper inspection.
- **PagerDuty** — for time-critical engagements or after-hours approvals.
- **Email** — fallback.

## Bundle approvals (with constraints)

An approver can pre-approve a sequence ("all web-auth-bypass attempts on `api.acme.example.com` for the next 30 minutes"). Bundles carry:
- Named technique class.
- Explicit target scope (narrower than or equal to artifact scope).
- Time window (≤ engagement window).
- Max action count.

Bundles do NOT cover persistence, privilege escalation, or cross-host lateral movement — those always require per-action approval.

## Quorum

- Default: 1 approver.
- Persistence, PII extraction, cloud-admin privesc: 2 approvers (engagement lead + client representative).

## Timeout behavior

- **Not critical**: timeout = auto-reject; action dropped; operator paged.
- **Critical (actively compromising)**: escalate up the call chain.
- **Never auto-approve on timeout.**

## Adversarial hygiene

- Approval messages rendered by platform from structured data, not raw agent output (prevents prompt-injection into the approver's card).
- Every approval carries a cryptographic receipt; verifiable in the Cipher-Sec dashboard.
- Approver identity verified via SSO with hardware-key step-up for destructive approvals.

## Failure modes

| Mode | Defense |
|---|---|
| Approval fatigue ("approve-all" habit) | Per-approver rate + pattern analysis; team-lead sees rubber-stamping stats |
| Spoofed approval | Receipts + SSO step-up |
| Approver offline | Multi-channel cascade; pager fallback |
| Timeout on critical | Paged escalation; structured call chain |
| Rubber-stamp bundles | Bundles cannot cover persistence / privesc / cross-host |

## Metrics

- `hitl.proposals` by class (recon / exploit / privesc / persistence / exfil)
- `hitl.approval_latency_ms` p50 / p95
- `hitl.timeout_rate`
- `hitl.rubber_stamp_indicator` per approver
- `hitl.bundle_approval_rate`
