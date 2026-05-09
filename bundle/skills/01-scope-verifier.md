---
name: scope-verifier
description: Two-signature scope artefact verification.
---
# Scope Verifier

Every action verifies against the scope artefact:

```yaml
scope:
  engagement_id: 2026-05-09-pentest-acme
  targets:
    - 10.0.1.0/24
    - acme.example.com
  in_scope_actions:
    - port-scan
    - credential-spray
    - http-fuzz
  out_of_scope_actions:
    - data-exfiltration
    - destructive-ops
  signatures:
    authorizer:
      identity: ciso@acme.example.com
      signature: <base64>
      issued_at: 2026-05-09T08:00:00Z
    executor:
      identity: redteam-lead@security-vendor.com
      signature: <base64>
      issued_at: 2026-05-09T09:00:00Z
  expires_at: 2026-05-15T17:00:00Z
```

Both signatures must verify against pre-registered keys; expired
or single-signed scopes deny every action.

`LBL-CIPHER-SCOPE`: scope violations are denied, not warned.
