---
name: hmac-audit
description: Hash-chained HMAC audit log per engagement.
---
# HMAC Audit

Every action emits a row to the audit log:

```yaml
audit_row:
  ts: 2026-05-09T10:42:31Z
  engagement_id: 2026-05-09-pentest-acme
  role: attacker
  action: port-scan
  target: 10.0.1.42
  prev_hash: <hex>
  row_hmac: <hex>
```

Each row's HMAC binds to the previous row's hash, forming a chain.
Tampering with any row breaks the chain at install time
(`LBL-CIPHER-AUDIT`).

Audit logs ship to a per-engagement append-only sink configured at
install time.
