"""Scope authorization — HMAC-signed (for MVP) artifacts required for every action.

Production deploys JWS with per-principal Ed25519 keys; MVP uses HMAC-SHA256 with
a shared dev signing key so the test suite is self-contained.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from .models import Action, ScopeArtifact


class SignatureError(Exception):
    """Raised when signature verification fails."""


def _canonical_bytes(artifact: ScopeArtifact) -> bytes:
    payload = {
        "id": artifact.id,
        "engagement_id": artifact.engagement_id,
        "client": artifact.client,
        "targets": list(artifact.targets),
        "technique_allowlist": list(artifact.technique_allowlist),
        "technique_denylist": list(artifact.technique_denylist),
        "window_start": artifact.window_start,
        "window_end": artifact.window_end,
        "operators": list(artifact.operators),
        "max_concurrent_actions": artifact.max_concurrent_actions,
        "hitl_channel": artifact.hitl_channel,
        "issued_at": artifact.issued_at,
    }
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


@dataclass
class ScopeAuthorizer:
    """MVP authorizer using HMAC-SHA256 with per-principal shared keys.

    `keys` maps principal → secret. `required_principals` are the set of keys
    whose signatures must be present for an artifact to be valid. Default is
    ``{"client", "engagement_lead"}`` to enforce the two-signature rule.
    """

    keys: dict[str, str]
    required_principals: frozenset[str] = frozenset({"client", "engagement_lead"})

    def sign(self, artifact: ScopeArtifact, principal: str) -> None:
        if principal not in self.keys:
            raise KeyError(f"no signing key for principal {principal!r}")
        mac = hmac.new(
            self.keys[principal].encode("utf-8"),
            _canonical_bytes(artifact),
            hashlib.sha256,
        ).hexdigest()
        artifact.signatures[principal] = mac

    def verify(self, artifact: ScopeArtifact) -> None:
        """Raise SignatureError if the artifact is not valid right now."""
        now = time.time()
        if now < artifact.window_start:
            raise SignatureError("artifact not yet valid (before window_start)")
        if now > artifact.window_end:
            raise SignatureError("artifact expired (after window_end)")

        missing = self.required_principals - artifact.signatures.keys()
        if missing:
            raise SignatureError(f"missing required signatures from: {sorted(missing)}")

        canonical = _canonical_bytes(artifact)
        for principal, provided in artifact.signatures.items():
            key = self.keys.get(principal)
            if key is None:
                raise SignatureError(f"unknown signing principal {principal!r}")
            expected = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, provided):
                raise SignatureError(f"invalid signature for principal {principal!r}")

    # -- action-level scope checks ---------------------------------------------

    @staticmethod
    def action_in_scope(action: Action, artifact: ScopeArtifact) -> tuple[bool, str]:
        """Return (allowed, reason). `reason` non-empty only when False."""
        if action.engagement_id != artifact.engagement_id:
            return False, "engagement_id mismatch"

        # Target match against CIDR/FQDN globs (glob semantics for MVP; prod uses ipaddress for CIDR)
        if not any(
            fnmatch.fnmatchcase(action.target, pat) or action.target == pat
            for pat in artifact.targets
        ):
            return False, f"target {action.target!r} not in scope targets"

        # Technique checks
        if any(fnmatch.fnmatchcase(action.technique, pat) for pat in artifact.technique_denylist):
            return False, f"technique {action.technique!r} matches denylist"
        if not any(fnmatch.fnmatchcase(action.technique, pat) for pat in artifact.technique_allowlist):
            return False, f"technique {action.technique!r} not in allowlist"

        return True, ""
