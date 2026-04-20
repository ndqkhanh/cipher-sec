"""Recon layer — passive-first, active gated by scope artifact."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any

_PASSIVE_TECHNIQUES = {"recon.passive"}
_ACTIVE_TECHNIQUES = {
    "recon.active.portscan",
    "recon.active.subdomain",
}


@dataclass
class Asset:
    id: str
    kind: str            # host | service | endpoint | subdomain | cert
    target: str
    evidence: str
    technique: str


@dataclass
class ReconResult:
    assets: list[Asset] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _seeded_rand(seed: str) -> random.Random:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


class ReconLayer:
    """Mock recon — deterministic "findings" based on hashes of target strings.
    Swap with nmap / amass / httpx MCP adapters in production.
    """

    def can_run(self, technique: str, artifact_techniques: list[str]) -> tuple[bool, str]:
        if technique in _PASSIVE_TECHNIQUES:
            return True, ""
        if technique in _ACTIVE_TECHNIQUES:
            if technique in artifact_techniques or any(
                technique.startswith(pat.rstrip("*")) for pat in artifact_techniques
            ):
                return True, ""
            return False, f"active technique {technique!r} not in scope"
        return False, f"unknown recon technique {technique!r}"

    def run(self, target: str, technique: str) -> ReconResult:
        """Produce deterministic pseudo-findings for the given target/technique."""
        rng = _seeded_rand(f"{target}:{technique}")
        assets: list[Asset] = []
        notes: list[str] = []

        if technique == "recon.passive":
            # Simulate CT log + DNS lookup
            sub_count = rng.randint(2, 4)
            for i in range(sub_count):
                sub = f"sub{i+1}.{target}"
                assets.append(
                    Asset(
                        id=f"asset-{hashlib.md5(f'{target}-{i}'.encode()).hexdigest()[:8]}",
                        kind="subdomain",
                        target=sub,
                        evidence=f"CT log entry (mock) for {sub}",
                        technique=technique,
                    )
                )
            notes.append(f"passive recon returned {len(assets)} subdomains")

        elif technique == "recon.active.portscan":
            ports = rng.sample([22, 80, 443, 8080, 3306, 6379, 5432, 25], 3)
            for port in ports:
                assets.append(
                    Asset(
                        id=f"asset-{hashlib.md5(f'{target}-{port}'.encode()).hexdigest()[:8]}",
                        kind="service",
                        target=f"{target}:{port}",
                        evidence=f"TCP {port} open (mock)",
                        technique=technique,
                    )
                )
            notes.append(f"portscan found {len(assets)} open services")

        elif technique == "recon.active.subdomain":
            brute_count = rng.randint(3, 6)
            for i in range(brute_count):
                sub = f"brute{i+1}.{target}"
                assets.append(
                    Asset(
                        id=f"asset-{hashlib.md5(f'{target}-b-{i}'.encode()).hexdigest()[:8]}",
                        kind="subdomain",
                        target=sub,
                        evidence=f"subdomain enum (mock) {sub}",
                        technique=technique,
                    )
                )
            notes.append(f"subdomain brute discovered {len(assets)} names")

        return ReconResult(assets=assets, notes=notes)
