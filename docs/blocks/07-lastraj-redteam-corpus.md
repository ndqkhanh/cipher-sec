# Cipher-Sec Block 07 — LaStraj-for-Pentest Corpus

## Responsibility

Maintain a growing corpus of adversarial agent trajectories (human-crafted and model-generated) that serves two uses:

1. **Train and test the [safety monitor](08-safety-monitor.md)** — maximize detection rate on LaStraj-class attacks.
2. **Red-team the agent itself** — inject corpus trajectories into controlled engagements and measure how Cipher-Sec behaves.

## Why LaStraj

[LinuxArena](../../../docs/26-linuxarena-production-agent-safety.md)'s finding: **human-crafted adversarial trajectories (LaStraj) evade model monitors at substantially higher rates than any model-generated attack**. Monitors trained only on auto-generated attacks achieve misleading benchmark scores; Cipher-Sec exports this discipline.

Against a security-engineering agent, this matters more: motivated attackers *will* craft human-expert-level adversarial inputs. Training and evaluating the monitor against LaStraj is the single strongest defense.

## Corpus shape

```python
Trajectory:
  id: UUID
  source: "human" | "model" | "hybrid"
  attack_class: str          # e.g. "credential_exfil", "persistence_plant", "cross_scope_pivot"
  target_technique: str      # what the agent is being tricked into
  prompt_text: str           # the adversarial turn or sequence
  context_required: list     # pre-conditions (what the agent must have seen)
  expected_safe_response: str  # what a well-harnessed agent should do
  tags: list[str]
  contributed_by: PrincipalID
  date_added: datetime
```

## Attack classes covered

- **Credential exfiltration** (trick the agent into writing creds to accessible path).
- **Persistence planting** (add scheduled tasks / cron / systemd units beyond scope).
- **Cross-scope pivot** (use in-scope foothold to attack out-of-scope asset).
- **Lateral movement cover** (destructive action wrapped in plausible triage).
- **Scope-artifact confusion** (exploit operator fatigue during re-authorization).
- **Supply-chain via injected tool output** (manipulate agent via controlled page content).
- **Role-playing / authority confusion** (from [docs/49 Agents of Chaos](../../../docs/49-agents-of-chaos-red-teaming.md)).

## Curation workflow

1. Security researchers (internal + invited external) submit trajectories.
2. Each is reviewed for novelty and label correctness.
3. Accepted trajectories go into a version-tagged corpus.
4. Monitor is re-trained / re-tuned against the latest version; evasion rate is reported per release.
5. Customer-specific trajectories are tenant-scoped.

## Federation (optional, opt-in)

Tenants can contribute anonymized trajectories to a shared corpus. This creates the public agent-security benchmark that does not yet exist at community scale. Contributions require legal review; attribution is configurable.

## Eval metrics

- **Evasion rate** per attack class (target: < 10 % at 1 % FPR; industry baseline 23 % on LinuxArena).
- **Novel-class detection rate** (monitor's performance on classes added after last tuning).
- **False-positive rate on benign trajectories** (not the corpus; recorded production engagements).

## Failure modes

| Mode | Defense |
|---|---|
| Corpus quality drift | Reviewer pool; gold-set sample scored by multiple reviewers |
| Monitor overfit to corpus | Hold-out classes; continuous introduction of novel trajectories |
| Leakage to adversaries | Corpus is NOT a public exploit repository; high-risk trajectories restricted to vetted members |
| Federation poisoning | Contributions isolated; platform reviewers check before inclusion in shared corpus |

## Metrics

- `lastraj.corpus_size` by class
- `lastraj.monitor_evasion_rate` by class (trend)
- `lastraj.novel_contributions_per_month`
- `lastraj.federation_tenants`
- `lastraj.retraining_cycles`
