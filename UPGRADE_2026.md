# Cipher-Sec — May-2026 Upgrade Stub

> Companion to [`../CROSS_PROJECT_UPGRADE_PLAN_2026.md`](../CROSS_PROJECT_UPGRADE_PLAN_2026.md).
> Per the cross-project matrix, Cipher-Sec is **W3** — security
> domain; dual-use guardrails first-class; HITL gate stays in
> cipher-sec, not in Lyra core.

## Headline gap (vs 2026 SOTA)

- **No `bundle/`** — scope verifier + deny engine + HMAC audit not
  packaged.
- **Scope artefacts not portable** — two-signature scope artefacts
  are the project's headline primitive; they should be representable
  as a Lyra Talent envelope ([`L38-4`](../lyra/LYRA_V3_8_ARGUS_INTEGRATION_PLAN.md))
  so other harnesses can verify them.
- **HITL gate** — exploit execution requires a human-in-the-loop
  approval step that *must not* run in Lyra core; install must fail
  closed if the Lyra runtime cannot deliver the gate.

## Smallest upgrade

```text
cipher-sec/bundle/
├── bundle.yaml                # dual_use: true (offensive security)
├── persona.md
├── skills/
│   ├── 01-scope-verifier.md
│   ├── 02-deny-engine.md
│   ├── 03-hmac-audit.md
│   ├── 04-hitl-exploit-gate.md
│   └── 05-attacker-defender-mutex.md
├── tools/
│   └── mcp_server.py          # scope verify + deny + audit + HITL queue
├── memory/
│   └── seed.md                # default deny rules
├── evals/
│   ├── golden.jsonl           # LaStraj + LinuxArena safety + pentest probes
│   └── rubric.md
└── verifier/
    └── checker.py             # scope authorization + deny-engine verifier
```

## Bright lines

- `LBL-CIPHER-DUAL` — `dual_use: true` enforced by L311-5 install gate.
- `LBL-CIPHER-SCOPE` — every action verified against a two-signature
  scope artefact; install fails closed without a verifying signer.
- `LBL-CIPHER-HITL` — exploit-class actions require a human approval
  hook delivered by the runtime; install fails closed if the runtime
  cannot deliver.
- `LBL-CIPHER-MUTEX` — attacker / defender role per engagement;
  enforced in the bundle's MCP server.

## Test plan

- 9+ tests covering scope verifier round-trip, deny engine semantics,
  HITL gate emission + block path, attacker/defender mutex, and
  install-failure when HITL undeliverable.

## Sequencing

W3 — depends on Lyra v3.11 L311-1 + L311-4 + L311-5.

## Related Lyra phases

- L311-1 Agent Teams runtime — `team.hitl_required` lifecycle event
  added by this bundle.
- L311-5 AgentInstaller — `LBL-BUNDLE-DUAL-USE` gate + HITL channel
  check.
