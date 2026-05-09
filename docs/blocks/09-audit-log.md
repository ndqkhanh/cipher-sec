# Cipher-Sec Block 09 — Append-Only Audit Log

## Responsibility

Every action, decision, approval, denial, and state transition is written to an append-only hash-chained log, signed with per-tenant keys. External auditors can verify the chain without reading protected content.

References: [docs/24 observability](../../../docs/24-observability-tracing.md), [docs/38 Claw-Eval cross-channel evidence](../../../docs/38-claw-eval.md).

## Entry shape

```json
{
  "seq": 147352,
  "engagement_id": "...",
  "scope_artifact_id": "...",
  "action_id": "...",
  "principal": "alice@pentest.example",
  "approver": "lead@pentest.example",
  "tool": "sqlmap",
  "args_hash": "sha256:...",
  "decision": "asked_and_approved",
  "policy_rules_fired": ["deny.os-pwn-absent"],
  "before_snapshot_hash": "sha256:...",
  "after_snapshot_hash": "sha256:...",
  "result_hash": "sha256:...",
  "monitor_verdict": {"level": 0, "classes": []},
  "prev_entry_hash": "sha256:...",
  "entry_hash": "sha256:...",
  "signature": "ed25519:...",
  "ts": "2026-04-22T13:45:22Z"
}
```

## Integrity properties

- **Hash chain.** Each entry includes the previous entry's hash — tampering with any entry invalidates the chain from that point.
- **Per-tenant signing key.** HSM/KMS-backed. Public keys published for external verification.
- **Write-ahead discipline.** The audit entry is persisted BEFORE the effect hits the target system. If the process crashes between entry-write and effect, the audit records "intent"; operator reconciles manually.
- **No entry deletion.** Compliance-motivated redaction is a new entry that references the old; original is preserved with its sensitive fields hashed.

## Cross-channel evidence (Claw-Eval pattern)

For the strong "exploit confirmed" claim in a finding, three channels must agree:

1. **Trace** — agent's own record of what it did.
2. **Target audit log** — target system / client-side evidence (e.g., successful auth attempt observed).
3. **Before/after snapshot diff** — observed state change matches expected effect.

Mismatch → finding flagged "ambiguous" (not "confirmed") until human review.

## Retention

- Minimum 7 years for pentest engagement audits (industry standard).
- Minimum 1 year for safety forensic snapshots.
- Per-tenant override for stricter jurisdictions.

## External verification endpoint

```
GET /v1/engagements/{id}/audit/verify
  → { chain_intact: bool,
      entries: int,
      signatures_valid: int,
      first_hash: "...",
      last_hash: "...",
      public_key_fingerprint: "..." }
```

Clients can run their own verifier against their public key without trusting the platform.

## Key rotation

- Rotate tenant signing keys on schedule (yearly default) or on-demand (post-incident).
- Old keys archived for historical verification; new engagements use new keys.
- Rotation event itself is audit-logged.

## Failure modes

| Mode | Defense |
|---|---|
| Write-ahead failure | Action refused; fail closed |
| Chain-verify fail | Engagement enters read-only; operator paged; no new actions |
| Key compromise | Revocation + mandatory re-signing of affected engagements' open sections |
| Storage backend loss | Replicated off-site; integrity check on recovery |
| Unintended content in args_hash | Args are hashed; content scrubber runs on any auxiliary fields |

## Metrics

- `audit.entries_per_engagement`
- `audit.chain_verification_pass_rate` (target 100%)
- `audit.key_rotation_events`
- `audit.cross_channel_mismatch_rate` (findings flagged ambiguous)
- `audit.external_verification_checks` (customer usage)
