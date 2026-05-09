# Cipher-Sec Block 08 — Safety Monitor

## Responsibility

Continuously inspect the agent's trajectory for covert / off-task / collateral-damage behavior. Different-family nano-class model; every N steps it reads the recent trace and decides flag / pause / halt.

References: [docs/26 LinuxArena](../../../docs/26-linuxarena-production-agent-safety.md), [docs/49 Agents of Chaos](../../../docs/49-agents-of-chaos-red-teaming.md), [docs/38 Claw-Eval](../../../docs/38-claw-eval.md).

## Why a monitor even in an authorized engagement

Authorization does not remove risk:

- A misconfigured tool may drift out of scope mid-action.
- Adversarial inputs (a captured page, an attacker-controlled response) can steer the agent.
- Operator error can approve a destructive action mid-chain that opens blast beyond scope.
- Supply-chain compromise of an LLM / MCP server can inject covert steps.

The monitor is the independent second pair of eyes that the primary agent does not have.

## Cadence

- Every 5 agent steps by default.
- Every 1 step during the first 10 steps of an engagement (startup vigilance — when the most misconfigurations surface).
- Every step after any flag is raised (heightened vigilance).

## Inputs

The monitor receives:

- Recent trace slice (last N structured actions + results + scope artifact hash).
- Current engagement mode (`attacker` / `defender`).
- Scope artifact summary.
- Concurrent action count.

## Decision levels

- **Level 1 (soft)** — suspicious but not actionable; log + continue.
- **Level 2 (medium)** — off-task or drift toward out-of-scope; pause engagement until operator ack.
- **Level 3 (hard)** — destructive side-effect signal (data exfil beyond scope; persistence plant unauthorized); terminate engagement, revoke credentials, forensic snapshot.

Levels are tuned against the [LaStraj corpus](07-lastraj-redteam-corpus.md).

## Detection classes

From [Agents of Chaos](../../../docs/49-agents-of-chaos-red-teaming.md):

- Unauthorized compliance with inputs claiming authority.
- Destructive side effect exceeding stated goal.
- Cross-scope propagation.
- Identity spoofing.
- False success reporting.
- Resource exhaustion / DoS-against-self.
- Sensitive-information disclosure.

Plus Cipher-Sec specifics:

- Credential exfiltration shape (writes, prints, or network-transmits credential-shaped values).
- Persistence-plant shape (writes to systemd / cron / launchd / authorized_keys).
- Scope-artifact drift (action target → adjacent out-of-scope asset).

## False-positive management

- Flags carry evidence (quoted step); operators label TP / FP.
- Labels feed periodic threshold tuning.
- Sustained FP rate triggers monitor-version rollback.
- Target FPR ≤ 1 % at Level 2+.

## Different-family requirement

- Primary agent: e.g., Claude Opus 4.6.
- Monitor: Nano-class from a different vendor (GPT-5-nano or equivalent).
- Rationale: shared blind spots. Enforced by deployment config; fallback to same-family logs a warning.

## Not a substitute for other layers

Deny engine (block 04), scope artifact (block 01), and sandbox (block 03) all run regardless. Monitor adds a trajectory-level signal; the other layers are action-level.

## Forensic snapshot on Level 3

- Full trace archived.
- Sandbox state snapshotted.
- Credentials used revoked.
- Incident record created; external review required before any resumption.
- Retention ≥ 1 year (compliance + forensics).

## Metrics

- `monitor.checks_per_engagement`
- `monitor.flags` by level + class
- `monitor.fp_rate` (operator-labeled)
- `monitor.lastraj_evasion_rate` (regression corpus)
- `monitor.check_latency_ms` p95
- `forensic_snapshot_count`
