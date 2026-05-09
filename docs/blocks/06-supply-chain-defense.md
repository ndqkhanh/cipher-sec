# Cipher-Sec Block 06 — Supply-Chain Defense

## Responsibility

Protect Cipher-Sec itself from supply-chain compromise — malicious LLM routers, tampered MCP servers, poisoned tool wrappers. Security engineering prompts routinely carry scope artifacts, internal credentials, and partial exploit chains; a compromised intermediary is a breach.

Reference: [docs/35 malicious-intermediary-attacks](../../../docs/35-malicious-intermediary-attacks.md) (arXiv:2604.08407 — 428 routers surveyed; active injection, credential theft documented).

## Defense layers

### 1. Direct LLM endpoints, no third-party routers

Cipher-Sec talks to Anthropic / OpenAI / local inference servers directly. Routers ("LLM as a service" aggregators) are forbidden by default. If a tenant contractually requires a router, it must expose:
- A transparency log of all in-flight requests.
- Response-anomaly screening (see below).
- A published integrity audit.

### 2. Append-only transparency log

Every LLM request and response is hashed and recorded with:

```json
{
  "ts": "...",
  "engagement_id": "...",
  "request_digest": "sha256:...",
  "response_digest": "sha256:...",
  "tokens_in": 1234,
  "tokens_out": 567,
  "model": "claude-3-5-sonnet-20250929",
  "prev_entry_hash": "sha256:...",
  "entry_hash": "sha256:..."
}
```

Chain verification matches the [audit log](09-audit-log.md) pattern.

### 3. Response-anomaly screening

Every LLM response inspected:
- Unexpected tool calls (tool name not in agent's registered tool set) → hard refuse.
- Tool-argument schema drift (extra fields, type mismatches) → hard refuse.
- Instruction-shape anomalies in what should be output ("ignore previous" phrases in response text) → flag and review.
- Latency anomalies (>3× baseline) → soft flag (possible router introspection).

### 4. MCP server discipline

- Every MCP server has a pinned image digest.
- Manifests are signed; signature verified at connect.
- Server capability list frozen at connection time; additions mid-session are refused.
- Capability schemas hashed; drift → disconnect + alarm.

### 5. Tool wrapper integrity

Tool wrappers (nmap, sqlmap, metasploit) are pinned versions. CI runs regression tests against known-good outputs on every image rebuild. A wrapper's output shape changing silently is a supply-chain signal.

### 6. Secrets never in prompts

- Scoped credentials flow from credential provider → sandbox → tool binary.
- Never pass credentials into the LLM's context.
- If tool output contains credential-shape values, the scrubber strips them before they re-enter the context.

## Red-team rotation

The [LaStraj corpus](07-lastraj-redteam-corpus.md) includes supply-chain attack trajectories; the monitor is periodically tested against them. Evasion rate above threshold triggers an incident.

## Defense levels on detection

- **Level 1 (soft)**: log + continue; operator sees a notice.
- **Level 2 (medium)**: pause the engagement; require operator ack.
- **Level 3 (hard)**: terminate the engagement; revoke credentials; forensic snapshot retained ≥ 1 year.

## Failure modes

| Mode | Defense |
|---|---|
| Router promises transparency, lies | Client-side transparency log; divergence detectable |
| MCP server silently upgraded | Digest pin; drift → disconnect |
| LLM vendor itself compromised | Out of scope — threat transfer to vendor's own controls |
| Tool-wrapper integrity check bypass | CI regression + runtime signature |

## Metrics

- `supply_chain.anomaly_flags` by class
- `mcp.version_drift_events`
- `mcp.capability_signature_failures`
- `transparency_log.reconciliation_failures`
- `secret_in_prompt_prevented_count` (should rise as new wrappers are added; then plateau)
