# Cipher-Sec Block 10 — Evidence Reporting

## Responsibility

Render engagement findings into structured, reproducible, legally-defensible reports: CVSS-scored vulnerabilities, concrete PoC steps pinned to the audit log, and an engagement summary with scope citations.

## Finding schema

```python
Finding:
  id: UUID
  engagement_id: UUID
  title: str                 # "Authenticated RCE in /api/uploads"
  severity: "critical" | "high" | "medium" | "low" | "info"
  cvss:
    version: "3.1" | "4.0"
    base_score: float
    temporal_score: float | null
    vector: str
  affected_assets: list[AssetRef]
  reproducible_steps: list[ActionRef]   # ordered audit-log pointers
  evidence_refs: list[ChunkRef]
  confirmed: bool                       # cross-channel evidence agrees
  remediation_hint: str
  compensating_controls_observed: list[str]
  discovered_at: datetime
```

## Every finding is reproducible by audit replay

The `reproducible_steps` field lists audit-log entry IDs in execution order. The client can, using their own verified copy of the audit log, replay the finding:

1. Obtain scope artifact (already signed).
2. Obtain audit entries referenced.
3. In a fresh sandbox, re-execute the same tool calls with the same args (or dry-run where supported).

This is much stronger than the prose-only PoCs many pentest reports ship.

## Report surfaces

### Operator dashboard

Interactive view with:
- Findings list, filterable by severity, asset, technique class.
- Per-finding trace drill-down (click finding → see audit entries → see tool output chunks).
- Scope artifact annotation on each finding (which scope authorization covered it).
- Cross-channel evidence status (confirmed / ambiguous / rejected).

### Client PDF / HTML report

Structured sections:

1. **Executive summary** — scope artifact reference, engagement window, findings by severity.
2. **Findings** — one section per finding, ordered by severity; includes CVSS vector, reproducible steps (audit entry IDs), evidence snippets.
3. **Appendix A: Scope artifact** — the signed artifact verbatim.
4. **Appendix B: Audit summary** — entry count, chain integrity check, public key fingerprint.
5. **Appendix C: Tooling** — list of tool versions used with their image digests.
6. **Appendix D: Negative results** — attempted techniques that did not succeed, with brief notes.

### Structured export

- JSON following a community schema (SARIF or custom).
- DefectDojo / Nucleus integration for findings-management systems.

## PII / sensitive-data handling

- Evidence snippets are passed through a redactor before inclusion in the report.
- Redaction preserves structural shape (so the client can unredact in their secure environment if needed).
- Original un-redacted evidence stays in the engagement's sealed audit bundle; report gets the redacted view.

## Authenticity

- Report signed by the engagement lead.
- Includes `audit.last_hash` + `scope_artifact.hash` + `engagement.id` so the client can verify the report corresponds to a specific audit-log state.

## Failure modes

| Mode | Defense |
|---|---|
| Fabricated findings | Every finding's `reproducible_steps` must resolve in the audit log; validator checks at report generation |
| Missing negative results | Schema requires Appendix D to be non-empty for engagement close |
| PII leakage in evidence snippets | Pre-render redactor; CI test with known PII shapes |
| Report-audit desynchronization | Report metadata includes audit hash at time of rendering |

## Metrics

- `reporting.findings_per_engagement` distribution
- `reporting.unconfirmed_finding_rate` (cross-channel evidence mismatch rate)
- `reporting.replay_verification_rate` (clients re-running PoCs)
- `reporting.pdf_generation_latency_ms` p95
- `reporting.sarif_export_count`
