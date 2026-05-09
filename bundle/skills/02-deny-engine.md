---
name: deny-engine
description: Deny-first action policy.
---
# Deny Engine

Every action runs through the deny engine before execution:

1. Match against the engagement's `out_of_scope_actions` list.
2. Match against the global default deny-list (`rm -rf /`, fork
   bomb, drop database, mass DNS exfiltration).
3. Match against the deny-list for the active role (attacker vs
   defender — see `attacker-defender-mutex`).
4. Default to **deny** if no explicit allow rule matches.

The engine emits `cipher.deny.{rule_id}` on every denial. Denials
are surfaced to the user but never auto-retried.
