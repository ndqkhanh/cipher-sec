# Cipher-Sec — Architecture Trade-offs

## Trade-off 1: Scope Authorization as cryptographic artifact vs config file

**Chosen:** Signed artifact enforced at the runner layer.

**Alternative:** YAML policy file per engagement (like Aegis-Ops).

**Why:** Pentest engagements have legal exposure. A signed artifact with enumerated targets, techniques, and window gives auditors a single, tamper-evident source of truth. A misconfigured YAML is a legal liability; a tampered signature breaks cryptographically.

**Cost:** Key management per engagement. Worth it.

## Trade-off 2: Mutually-exclusive attacker/defender modes vs blended

**Chosen:** Mutual exclusion per account per target.

**Alternative:** One account, context-aware mode switching.

**Why:** [Agents of Chaos](../../docs/49-agents-of-chaos-red-teaming.md) documented cross-mode confusion as a recurring failure. An agent running both attack and defense on the same target can inadvertently feed one mode's findings to the other. Explicit mutual exclusion is the cheapest elimination.

**Cost:** Operator UX friction on mixed-purpose engagements (rare).

## Trade-off 3: HITL default-on for destructive vs confidence-gated skip

**Chosen:** Always HITL for destructive.

**Alternative:** Let high-confidence actions auto-run.

**Why:** Self-reported confidence is not a trustworthy signal, especially when adversaries manipulate it (same argument as Aegis). Destructive actions on authorized targets still have non-zero risk of collateral damage.

**Cost:** Latency during engagement. Mitigated by async approval channels (Slack/Teams) and bundle-approval patterns.

## Trade-off 4: Different-family safety monitor vs same-family

**Chosen:** Different family; nano-class (GPT-5-nano-equivalent).

**Alternative:** Same family as generator.

**Why:** LaStraj-class attacks evade same-family monitors at much higher rates. A mixed-family stack breaks the shared-blind-spot symmetry.

**Cost:** Two vendor relationships. Failover to same-family with warning where vendors coincide.

## Trade-off 5: Continuous monitor cadence vs end-of-engagement only

**Chosen:** Every N steps (default 5) + end-of-engagement.

**Alternative:** End-only, because security engagements are long.

**Why:** Sabotage unfolds over many steps before the "payload" action. Catching mid-stream is cheaper than rolling back a compromised environment.

**Cost:** Monitor LLM calls. Nano-tier keeps cost trivial.

## Trade-off 6: Policy deny-list is hard-coded vs per-tenant customizable

**Chosen:** Hybrid — a platform deny-list (never touch identity providers, never plant persistence on critical systems) plus per-tenant deny/allow overrides.

**Alternative:** Fully per-tenant.

**Why:** Some rules are non-negotiable (identity provider modification, cross-tenant data movement). Others (allowed DNS enumeration scope) vary per engagement.

**Cost:** Platform deny-list must be maintained and versioned centrally.

## Trade-off 7: Recon defaults to passive-only vs active-by-default

**Chosen:** Passive-first; active requires a scope-upgrade artifact.

**Alternative:** Active scanning by default for bounded scopes.

**Why:** Passive recon has zero blast radius and is almost always legal on any target in scope. Active scanning (port scans, fingerprinting) can trigger client IDS, raise alarms, be flagged as "attack" even with authorization. Requiring explicit upgrade forces operators to coordinate with the client first.

**Cost:** One more approval step per engagement. Small relative to legal risk avoided.

## Trade-off 8: Bring-your-own-tool (Metasploit/Burp/Nmap) vs built-in

**Chosen:** Orchestrate existing tools via MCP wrappers; do not build a new exploitation framework.

**Alternative:** Bundle exploit primitives inside the agent.

**Why:** Existing tools are battle-tested, legally scrutinized, and each has its own CVE-coverage. Cipher-Sec's value is orchestration discipline + scope binding + HITL, not reinventing Metasploit.

**Cost:** Integration surface is broad; per-tool MCP adapters must be maintained.

## Trade-off 9: Supply-chain defense required vs optional

**Chosen:** Required — no third-party LLM routers without transparency log and anomaly screening.

**Alternative:** Optional for convenience.

**Why:** [Malicious Intermediary Attacks](../../docs/35-malicious-intermediary-attacks.md) documented active credential theft via compromised routers. Security engineering prompts routinely contain scope artifacts, target IPs, and sometimes internal credentials; a compromised router is a breach vector.

**Cost:** Multi-vendor support needs direct integrations. Acceptable.

## Trade-off 10: Audit log is tenant-scoped + signed vs central unsigned

**Chosen:** Hash-chained append-only log per engagement, signed with a per-tenant key.

**Alternative:** Central (platform-operator-owned) log.

**Why:** Pentest audit trails have legal weight. Client must be able to verify integrity without trusting us. Signing per-tenant + external verification endpoint achieves that.

**Cost:** Key management. Standard.

## Rejected alternatives

- **Autonomous "closed-loop" red team.** Current capability and monitor effectiveness do not justify removing HITL on destructive actions.
- **Shared deny-list with Aegis-Ops.** Different threat models; shared list would be too permissive for Cipher-Sec or too restrictive for Aegis.
- **Model-side "will you exploit this CVE for me?" refusal as the only safety layer.** Model refusals are bypassable by framing; defense in depth is mandatory.
- **Monitor powered by the same LLM as the agent.** Shared blind spots make the monitor near-useless against motivated attackers.

## What breaks outside the design envelope

- **Engagements without legal authorization** — Cipher-Sec refuses to operate without a signed scope artifact. Not a stealth tool.
- **Purely autonomous bug bounty at scale** — the HITL bottleneck is real; Cipher-Sec is for engagements with active operators, not unattended swarms.
- **Clients who cannot sign a scope artifact** (legal or ops maturity gaps) — onboarding includes a scope-artifact workshop; skipping is not supported.
