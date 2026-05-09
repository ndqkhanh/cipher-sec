# Cipher-Sec Block 04 — Policy Deny Engine

## Responsibility

Enforce hard-deny rules that outrank everything — even signed scope artifacts, bundle approvals, and HITL overrides. This is the last line that prevents Cipher-Sec from becoming a generic offensive tool.

References: [docs/06 permission modes](../../../docs/06-permission-modes.md), [docs/05 hooks](../../../docs/05-hooks.md), [docs/22 guardrails](../../../docs/22-guardrails-prompt-injection.md).

## Layered guardrail pattern (OpenAI April 2026)

The deny engine sits inside a broader layered guardrail stack:

1. **Input validation** (recon / action args shape, type, bounds).
2. **Scope artifact check** ([block 01](01-scope-authorization.md)).
3. **Tool-risk rating** (low / medium / destructive) — determined by the tool registry, not the caller.
4. **Hard deny rules** (this block — non-bypassable).
5. **HITL trigger** if destructive.
6. **Safety monitor** (runs continuously in parallel).
7. **Output filtering / evidence redaction** before report generation.

## Platform-level hard-deny rules (non-negotiable)

```yaml
deny:
  # Identity and privilege infrastructure
  - operation: "modify.identity_provider.*"
  - operation: "*.create_admin_user"
  - operation: "*.disable_mfa"

  # Cross-tenant and cross-scope movement
  - operation: "*.egress"
    target_not_in_scope: true
  - operation: "data.cross_tenant.*"

  # Availability attacks beyond scope
  - operation: "ddos.*"
  - operation: "resource_exhaustion.*"

  # Persistence mechanisms without explicit engagement-level authorization
  - operation: "persistence.*"
  - operation: "lateral_movement.to_unscoped.*"

  # Known-destructive commands regardless of tool
  - pattern_in_args: ["rm -rf /", ":(){:|:&};:", "dd if=.* of=/dev/", "mkfs"]

  # Supply-chain compromise tool classes
  - tool_class: ["rootkit.*", "backdoor.*"]
```

Per-tenant rules can *add* denies but cannot remove platform denies.

## Evaluation order

Per action:

1. Match against platform deny rules — if any match, refuse (audit + short-circuit).
2. Match against tenant deny rules — if any match, refuse.
3. Proceed to HITL / auto / ask per scope artifact.

Deny rules always win. A signed scope artifact cannot override platform-level denies.

## Structured pattern matching

Args are parsed (not naive substring). Shell arguments → AST; SQL → tokenizer; Nmap flags → parser. "Benign" commands like `echo 'rm -rf /tmp/x'` are allowed; `rm -rf /` inside a subshell is caught.

## Per-tool pre-checks

Specific tools have specific deny patterns beyond generics:

- `sqlmap`: `--os-pwn`, `--os-shell`, `--os-cmd` (OS takeover escalation) require explicit tenant+engagement-lead re-authorization.
- `metasploit`: specific exploit modules must be allowlisted per engagement.
- `nmap`: `--script vuln` requires scope artifact includes active scanning.

## Failure modes

| Mode | Defense |
|---|---|
| Deny rule mis-specified allows something bad | Rule changes go through CI with adversarial test cases |
| Arg parser mismatches rule shape | Rules write against parsed structures; linter catches stringy rules |
| Hot-reload races | Versioned rule snapshots; active engagement pins its snapshot |
| Tenant-rule-author mistakes | PR review; adversarial test cases in CI |

## Metrics

- `deny_engine.blocks` by rule id
- `deny_engine.platform_vs_tenant_block_ratio`
- `deny_engine.evaluation_latency_ms` p95
- `deny_engine.hot_reload_count`
- `deny_engine.adversarial_test_coverage` (regression suite size)
