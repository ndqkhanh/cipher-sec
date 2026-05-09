---
name: attacker-defender-mutex
description: Per-engagement role mutex (red-team OR blue-team, not both).
---
# Attacker / Defender Mutex

Every engagement has a single role: attacker (red-team) or defender
(blue-team). The bundle's MCP server enforces this at action-
dispatch time. Cross-role actions in the same engagement are
denied with `cipher.mutex.violation`.

Why? Cross-role actions in a single engagement break audit
attribution and confuse the deny-list (defenders need different
deny-lists than attackers). Splitting forces clean separation.

`LBL-CIPHER-MUTEX`: enforced in the bundle's MCP server, not in
Lyra core.
