# Cipher-Sec seed memory

## Default global deny-list

Actions that are *always* denied regardless of scope:

- `rm -rf /` (or any path resolving to root).
- Fork bombs, infinite-recursion patterns.
- Database drop / truncate without explicit scope authorization.
- Mass DNS exfiltration (>1000 queries / minute).
- Lateral movement to systems not in `targets`.

## Default exploit class taxonomy

| Class | Examples | Gate |
|---|---|---|
| `passive-recon` | nmap -sn, whois, DNS lookup | none |
| `active-scan` | port scan, http-fuzz | scope check |
| `credential` | password spray, kerberoast | scope + deny + log |
| `exploit` | RCE, priv-esc, exfil | scope + deny + HITL + log |

## Default audit sink

Audit rows ship to `~/.cipher-sec/audits/{engagement_id}.jsonl`
unless overridden at install time. The sink is append-only and
verified at every install (`LBL-CIPHER-AUDIT`).
