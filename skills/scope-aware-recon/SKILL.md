---
name: 'scope-aware-recon'
description: 'Run reconnaissance only against assets in the engagement scope manifest; strip credentials and scope artefacts before storing.'
version: '0.1.0'
triggers: ['recon', 'enumerate', 'discover']
tags: ['security', 'scope', 'engagement']
---

# Goal
Enumerate authorised targets from the engagement scope manifest and emit
findings that contain no credentials, no scope artefacts, and no
analyst-namespace metadata.

# Constraints & Style
- Read the scope manifest for the active `engagement_id`; refuse any
  target absent from `scope.targets[]`.
- Implicit-auth probes (cookies, ambient session) are denied even when
  the target is in scope — explicit creds only.
- Strip credentials, HMAC keys, and `engagement_id` from emitted skill
  bodies (regex + Shannon-entropy gate) before promotion.
- Bright-lines: `BL-CIPHER-SKILL-CROSS-ENGAGEMENT` (a skill from
  engagement A cannot be used in engagement B without re-authorisation),
  `BL-CIPHER-SKILL-EXFIL` (skills cannot embed creds / scope artefacts).

# Workflow
1. Load `scope.manifest` for the active engagement; abort if missing or
   expired.
2. Filter requested targets against `scope.targets[]`; deny outside-scope
   requests with the matched-rule reason.
3. Run recon tools through the deny-engine sandbox; capture output.
4. Apply the exfil-gate: regex `(?i)(api[_-]?key|secret|hmac|bearer)`
   plus entropy ≥ 4.5 → redact.
5. Emit findings tagged with `engagement_id`; write to
   `engagements/<engagement_id>/` namespace only.
