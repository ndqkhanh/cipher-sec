# Cipher-Sec Block 01 — Scope Authorization

## Responsibility

Every engagement carries a cryptographic **Scope Authorization Artifact** that enumerates the legal boundaries of the operation: targets, technique classes, time window, operators. Every action is verified against it at the runner layer; expired / missing / tampered artifacts fail closed.

This is the first-class novelty of Cipher-Sec — references: [docs/06 permission-modes](../../../docs/06-permission-modes.md), [docs/23 HITL](../../../docs/23-human-in-the-loop.md), [docs/35 Malicious Intermediary](../../../docs/35-malicious-intermediary-attacks.md).

## Artifact shape (JWS-signed)

```json
{
  "id": "engagement-2026-04-20-acme",
  "client": "acme.example.com",
  "targets": [
    {"kind": "cidr", "value": "203.0.113.0/24"},
    {"kind": "fqdn", "value": "*.api.acme.example.com"}
  ],
  "technique_allowlist": [
    "recon.passive", "recon.active.portscan",
    "web.auth.fuzz", "web.authz.bypass"
  ],
  "technique_denylist": [
    "ddos.*", "ransomware.*", "persistence.*"
  ],
  "window": {
    "starts": "2026-04-22T00:00:00Z",
    "ends":   "2026-04-29T23:59:59Z"
  },
  "operators": ["alice@pentest.example", "bob@pentest.example"],
  "max_concurrent_actions": 3,
  "hitl_channel": "slack:#engagement-acme-2026-04",
  "signed_by": [
    {"principal": "acme-cso@acme.example.com", "alg": "EdDSA", "sig": "..."},
    {"principal": "lead@pentest.example",      "alg": "EdDSA", "sig": "..."}
  ]
}
```

**Two signatures required**: client side + engagement-lead side. Single-signature artifacts are refused.

## Verification

Every action invokes a signature check:

1. Parse JWS; verify both signatures against published public keys.
2. Ensure `now` ∈ `window`.
3. Ensure action target is in the artifact's `targets` (CIDR or FQDN glob).
4. Ensure action technique matches `technique_allowlist` and **not** `technique_denylist`.
5. Ensure operator initiating the action is in `operators`.
6. Ensure concurrent-action cap is not exceeded.

Any failure → action refused; audit entry records the refusal reason.

## Artifact lifecycle

- **Draft**: proposed by engagement lead, not yet signed.
- **Signed**: both parties signed; artifact in force.
- **Suspended**: client or lead can pause the artifact; actions refused until resumed.
- **Consumed**: engagement closed; artifact archived; audit log sealed.

## Key management

- Per-principal signing keys (EdDSA or equivalent).
- Client's public keys fetched via well-known URL (HTTPS + pinning) or provided during onboarding.
- Engagement-lead keys in your own HSM / KMS.
- Rotation: old signatures remain verifiable (public keys archived); new engagements use current keys.

## Failure modes

| Mode | Defense |
|---|---|
| Expired artifact | Pre-action check; fail closed |
| Tampered JSON | Signature mismatch on any field |
| Missing signature | Refused at onboarding |
| Key compromise | Revocation list + mandatory re-sign of open artifacts |
| Artifact leakage | Non-secret by design (targets known to both parties); integrity > confidentiality |

## Metrics

- `scope.verifications` (pass/refuse)
- `scope.refusal_reasons` histogram
- `scope.active_engagements`
- `scope.artifact_revocations`
- `scope.signature_failures` (hot alarm)
