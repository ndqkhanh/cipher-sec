# Cipher-Sec Block 02 — Recon Layer

## Responsibility

Discover attack surface within scope with the least invasive technique first. Passive recon is always allowed; active recon requires a scope-artifact upgrade.

## Passive recon (always available in-scope)

- Certificate Transparency logs (crt.sh-class queries for FQDN discovery).
- Public DNS records: A/AAAA, CNAME, MX, TXT, SPF/DMARC, SRV.
- WHOIS and RDAP lookups.
- Cached search indexes (Shodan cached data without interactive probe).
- Public code-search (GitHub/GitLab) for leaked tokens or references within scope domain.
- Historical wayback snapshots of in-scope hosts.

All passive operations have **zero blast radius** — they do not touch the client infrastructure.

## Active recon (requires scope-artifact inclusion)

- Port scans (TCP SYN, UDP, service fingerprint).
- HTTP fingerprinting, tech-stack detection.
- Subdomain brute-force within the scope CIDR/FQDN.
- Sensitive-endpoint probing (`/admin`, `/.git`, `/robots.txt`).

Active recon techniques are only unlocked if `technique_allowlist` in the [scope artifact](01-scope-authorization.md) includes them. Each category must be enumerated (`recon.active.portscan`, `recon.active.subdomain-brute`, etc.); no wildcard upgrade.

## Rate and timing

- Passive: rate-limited to avoid upstream (crt.sh, PublicDNS) throttling.
- Active: per-target QPS caps derived from scope artifact; exceeding caps refuses further actions in that window.
- Time-of-day: some clients require off-hours active recon; artifact can encode a `preferred_window` within the overall engagement window.

## Tool choice

The recon layer wraps existing tools via MCP:

- `nmap` (port scanning, service detection).
- `masscan` (fast scan for large CIDRs).
- `amass` (subdomain discovery).
- `httpx` (HTTP probing).
- `subfinder` (passive subdomain).

Direct shell execution inside the sandbox; output parsed into structured findings.

## Outputs

Typed: each recon action produces a list of `Asset` records:

```python
Asset:
  id: UUID
  kind: "host"|"service"|"endpoint"|"subdomain"|"cert"|"cname"
  target: str                 # e.g. "api.acme.example.com:443"
  evidence: list[ChunkRef]    # raw output handles
  discovered_at: datetime
  recon_technique: str
```

## Feeding the exploit runner

Recon findings feed into the planner's next phase. An exploit-phase action referencing an asset must match an Asset record discovered during recon (no phantom targets).

## Failure modes

| Mode | Defense |
|---|---|
| Overly aggressive active scan triggers client IDS | Pre-announce in scope artifact; rate caps enforced |
| Recon leaks to third parties (e.g., searches) | Passive queries use tenant-controlled egress endpoints |
| False-positive asset discovery | Cross-confirm via multiple techniques before exploit phase |
| Stale DNS / cache | Re-verify critical assets just before exploit |

## Metrics

- `recon.passive.queries` by source
- `recon.active.actions` by technique
- `recon.assets_discovered` by kind
- `recon.rate_limit_trips`
- `recon.coverage_vs_scope` (enumerated assets vs scope target count)
