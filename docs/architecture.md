# Cipher-Sec — Architecture

## What Cipher-Sec is

Cipher-Sec is a **security agent** covering both sides of the fence: assisted vulnerability research / penetration testing on authorized targets (the "offensive" mode), and incident triage / threat hunting / defensive runbook execution (the "defensive" mode). Every action is bound to an explicit **scope authorization artifact** (target CIDR, technique class, time window) that is cryptographically signed; destructive exploit execution is always HITL-gated; every trajectory is continuously inspected by a LaStraj-style sabotage monitor.

Cipher-Sec is *not* Aegis-Ops. Aegis-Ops ([projects/aegis-ops](../aegis-ops/architecture.md)) is production-ops defensive automation inside your own infrastructure. Cipher-Sec is security engineering on your infrastructure or on authorized third-party targets — the threat model is harsher and the HITL posture is tighter.

## Honest baselines

| Baseline | Reported number |
|---|---|
| Claude Opus 4.6 on **LinuxArena** (sabotage detection) | ~23% undetected sabotage at 1% monitor FPR vs GPT-5-nano monitor ([docs/26](../../docs/26-linuxarena-production-agent-safety.md)) |
| **LaStraj** (human-crafted adversarial trajectories) | evades monitors at substantially higher rates than any model-generated attacks (same source) |
| **Agents of Chaos** (Northeastern) | 11 representative failure case studies: unauthorized compliance, sensitive disclosure, destructive actions, DoS, identity spoof, cross-agent propagation, false success reports ([docs/49](../../docs/49-agents-of-chaos-red-teaming.md)) |
| **Malicious Intermediary Attacks** | 428 routers surveyed; active injection attacks and credential theft documented in the wild ([docs/35](../../docs/35-malicious-intermediary-attacks.md)) |
| Generic "security copilot" products | unspecified public benchmark; typical failure: no scope binding, no audit integrity, eager tool use under social engineering |

## Design targets (hypotheses)

- **Sabotage detection.** <10% undetected sabotage at 1% monitor FPR on a LaStraj-class evaluation (less than half the Opus 4.6 baseline). **Assumption:** dual-monitor (trajectory + state-diff) + cross-channel evidence per [Claw-Eval](../../docs/38-claw-eval.md).
- **Scope binding.** Zero actions executed outside the signed scope artifact. **Assumption:** sandboxed executor refuses unsigned/expired authorizations.
- **HITL on destructive exploits.** 100% of actions classified as destructive (privesc, persistence, lateral movement, data exfiltration simulation) gated by a human decision within an approval window.
- **Supply-chain integrity.** Direct LLM provider endpoints only; tamper-evident transparency log on every call.

## Component diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                           Cipher-Sec                                  │
│                                                                       │
│   Operator → [Scope Authorization]  (signed artifact per engagement)  │
│                         │                                             │
│                         ▼                                             │
│                   [Mode Selector]                                     │
│                  ┌─────────────────┐                                  │
│                  │  defender | attacker  (mutually exclusive/session) │
│                  └─────────────────┘                                  │
│                         │                                             │
│          ┌──────────────┼──────────────┐                              │
│          ▼              ▼              ▼                              │
│    [Recon Layer]  [Policy+Deny]   [HITL Gate]                         │
│                         │                                             │
│                         ▼                                             │
│              [Sandboxed Exploit Runner]                               │
│                         │                                             │
│                         ▼                                             │
│         [Safety Monitor (LaStraj-style, continuous)]                  │
│                         │                                             │
│                         ▼                                             │
│              [Evidence Reporting + Audit]                             │
│                                                                       │
│   ↕ Supply-Chain Defense on LLM egress                                │
│   ↕ Observability + trace-export                                      │
└───────────────────────────────────────────────────────────────────────┘
```

## The ten architectural commitments

1. **Scope Authorization primitive** — every engagement has a signed artifact (target list, technique allow-list, time window, operator identity). The sandboxed runner refuses to execute anything outside it. See [blocks/01-scope-authorization.md](blocks/01-scope-authorization.md).
2. **Recon Layer** — passive first (DNS, certificate transparency, Shodan cached data), active only with explicit scope authorization upgrade. See [blocks/02-recon-layer.md](blocks/02-recon-layer.md).
3. **Sandboxed Exploit Runner** — isolated container / VM per engagement; scoped short-lived credentials; network egress allow-listed to the scope. See [blocks/03-sandboxed-exploit-runner.md](blocks/03-sandboxed-exploit-runner.md).
4. **Policy Deny Engine** — hard-deny rules beyond "scope mismatch": no modifications to identity providers, no data exfil to unknown endpoints, no persistence mechanisms without explicit approval. See [blocks/04-policy-deny-engine.md](blocks/04-policy-deny-engine.md).
5. **HITL on destructive actions** — every destructive action is queued to an approver with context, alternatives, expected effect, blast radius. See [blocks/05-hitl-on-destructive.md](blocks/05-hitl-on-destructive.md).
6. **Supply-Chain Defense** — direct LLM endpoints only; transparency log; response-anomaly screener; pinned MCP servers. See [blocks/06-supply-chain-defense.md](blocks/06-supply-chain-defense.md).
7. **LaStraj-for-Pentest Corpus** — curated adversarial-trajectory dataset (human and model-generated) used to train the monitor AND to red-team the monitor continuously. See [blocks/07-lastraj-redteam-corpus.md](blocks/07-lastraj-redteam-corpus.md).
8. **Safety Monitor** — different-family nano-class model that reads the trace every N steps, flags off-task / covert actions. See [blocks/08-safety-monitor.md](blocks/08-safety-monitor.md).
9. **Append-Only Audit Log** — hash-chained, signed per entry; external auditors can verify without reading content. See [blocks/09-audit-log.md](blocks/09-audit-log.md).
10. **Evidence Reporting** — findings rendered as structured PoCs with CVSS scoring, reproducible exploit steps, and explicit scope citation. See [blocks/10-evidence-reporting.md](blocks/10-evidence-reporting.md).

## Data flow for a typical pentest engagement

1. Operator uploads a **scope authorization artifact** (signed by both the client and the engagement lead).
2. Agent enters `attacker` mode, bound to that scope; a parallel `defender` session on the same operator account is refused.
3. Recon layer runs passive checks, enumerates targets in scope.
4. Planner proposes exploit chains. Policy deny catches out-of-scope or prohibited techniques.
5. Destructive steps (privesc, persistence) queue at the HITL gate; the approver sees command, expected effect, blast radius.
6. Sandboxed runner executes approved steps with scoped credentials; safety monitor watches for off-task actions (credential exfil, backdoor placement not justified by scope).
7. Findings accumulate as typed evidence; audit log hash-chains each action.
8. On engagement end: final report is generated with CVSS-scored PoCs; audit bundle is sealed and signed; scope authorization is marked consumed.

## Novel contributions (not present in cited systems)

1. **Scope Authorization as a cryptographic primitive, not a config.** A JWS-signed artifact enumerating (targets, techniques, window, operators). The sandboxed runner verifies the signature on every action; expired or mismatched artifacts fail closed. Novel combination of [Aegis-Ops's policy engine](../aegis-ops/blocks/02-permission-policy.md) with [Syndicate's handoff signing](../syndicate/blocks/03-handoff-protocol.md) applied to security engineering.
2. **Mutually-exclusive mode segregation** — an account in `attacker` mode on target X cannot also run `defender` mode; switching requires cryptographic re-authorization. Prevents conflicts of interest (monitoring + attacking same system simultaneously) and the "cross-mode confusion" failures Agents of Chaos documented.
3. **LaStraj-for-Pentest Corpus.** [LinuxArena](../../docs/26-linuxarena-production-agent-safety.md)'s insight — that human-crafted adversarial trajectories evade model monitors far better than model-generated attacks — applied offensively: the corpus is used to harden *our* monitor, and also as the red-team benchmark for external auditors.
4. **Cross-channel sabotage detection** applied to security engineering: trace + state diff + audit log must agree before a finding is declared "successfully exploited". Extends Claw-Eval's methodology into pentest reporting.

## Non-goals

- Not a general-purpose RAT or exploitation framework; not a replacement for purpose-built tools (Metasploit, Burp, etc.). Cipher-Sec *orchestrates* those tools within scope.
- Not an autonomous red-team; HITL on destructive actions is non-optional.
- Not a legal advice engine; scope authorization presumes external legal clearance.
- Not a substitute for an incident response team — augments, not replaces.

## Cross-references

- Trade-offs: [architecture-tradeoff.md](architecture-tradeoff.md)
- Operations: [system-design.md](system-design.md)
- Research base: [docs/26 LinuxArena](../../docs/26-linuxarena-production-agent-safety.md), [docs/35 Malicious Intermediary](../../docs/35-malicious-intermediary-attacks.md), [docs/49 Agents of Chaos](../../docs/49-agents-of-chaos-red-teaming.md), [docs/22 Guardrails](../../docs/22-guardrails-prompt-injection.md), [docs/23 HITL](../../docs/23-human-in-the-loop.md), [docs/38 Claw-Eval](../../docs/38-claw-eval.md).

## Status

Design specification, April 2026. Scaffold-quality. Not implemented. Target environment: self-hosted per-engagement, air-gapped deployment option for high-sensitivity clients.
