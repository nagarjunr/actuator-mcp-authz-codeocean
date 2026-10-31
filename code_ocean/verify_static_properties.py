"""verify_static_properties.py -- what the Code Ocean capsule actually verifies
without requiring a live ADAM-6060 on a reachable Modbus TCP network.

This is NOT a re-run of the 13-scenario hardware evaluation battery --
that requires real hardware (see code_ocean/README.md for why we don't fake
it). This script verifies the two properties that ARE checkable statically:

1. The zero-source-change retrofit property (scenario 7):
   mcp_server/adam_server.py, the vendor-facing tool-server module, must
   import neither the authorization package (policy_engine) nor the new
   safety-envelope package (mcp_server.safety_envelope).
2. Every module in this repository imports cleanly under the pinned
   dependency set (notably fastmcp==3.4.7), confirming the codebase is
   self-consistent and the version pin discussed in the project's Discussion
   section is the one actually required.
"""

from __future__ import annotations

import importlib
import inspect
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def check_zero_source_change() -> bool:
    import mcp_server.adam_server as adam_server

    source = inspect.getsource(adam_server)
    no_policy_import = "policy_engine" not in source
    no_safety_import = "safety_envelope" not in source
    print(f"[check 1/2] adam_server.py imports policy_engine: {not no_policy_import}")
    print(f"[check 1/2] adam_server.py imports safety_envelope: {not no_safety_import}")
    ok = no_policy_import and no_safety_import
    print(f"[check 1/2] zero-source-change retrofit property: {'PASS' if ok else 'FAIL'}")
    return ok


def check_modules_import_cleanly() -> bool:
    modules = [
        "ca.ca",
        "policy_engine.policy",
        "policy_engine.policy_signing",
        "policy_engine.audit_log",
        "policy_engine.middleware",
        "mcp_server.adam6060",
        "mcp_server.adam_server",
        "mcp_server.safety_envelope",
        "mcp_server.retrofit",
        "mcp_server.setup_ca_and_policy",
    ]
    all_ok = True
    for m in modules:
        try:
            importlib.import_module(m)
            print(f"[check 2/2] import {m}: OK")
        except Exception as e:
            print(f"[check 2/2] import {m}: FAILED ({type(e).__name__}: {e})")
            all_ok = False
    print(f"[check 2/2] all modules import cleanly: {'PASS' if all_ok else 'FAIL'}")
    return all_ok


def main() -> int:
    print("=" * 70)
    print("actuator-mcp-authz -- static verification (no hardware required)")
    print("See code_ocean/README.md for what this does and does NOT verify.")
    print("=" * 70)
    r1 = check_zero_source_change()
    r2 = check_modules_import_cleanly()
    overall = r1 and r2
    print("=" * 70)
    print(f"OVERALL: {'PASS' if overall else 'FAIL'}")
    print("=" * 70)
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
