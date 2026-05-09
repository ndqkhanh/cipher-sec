"""Cipher-Sec MCP server stub.

Tools published:

- ``cipher.scope_verify(scope)`` — two-signature check.
- ``cipher.deny_check(action, scope)`` — deny-first policy.
- ``cipher.audit_append(action, role)`` — hash-chained audit row.
- ``cipher.hitl_request(action)`` — exploit-class HITL gate.
- ``cipher.health()`` — adapter health.
"""
from __future__ import annotations

import json
import sys


def main() -> int:
    line = sys.stdin.readline()
    if not line.strip():
        print(json.dumps({"error": "no input"}))
        return 0
    req = json.loads(line)
    tool = req.get("tool", "cipher.health")
    args = req.get("args") or {}
    if tool == "cipher.scope_verify":
        print(json.dumps({"tool": tool, "result": {"valid": True, "signatures": 2}}))
    elif tool == "cipher.deny_check":
        print(json.dumps({"tool": tool, "result": {"allowed": True}}))
    elif tool == "cipher.audit_append":
        print(json.dumps({"tool": tool, "result": {"chained": True, "row_hmac": "<stub>"}}))
    elif tool == "cipher.hitl_request":
        print(json.dumps({"tool": tool, "result": {"approval_pending": True}}))
    elif tool == "cipher.health":
        print(json.dumps({"tool": tool, "result": {"ok": True}}))
    else:
        print(json.dumps({"tool": tool, "error": f"unknown tool {tool}"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
