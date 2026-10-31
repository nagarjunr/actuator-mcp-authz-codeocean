"""retrofit.py -- attaching LocalAuthorizationMiddleware (reused unmodified from
mcp-local-authz) AND SafetyEnvelopeMiddleware (new, physical-safety-specific) to the
real adam_server.py, with ZERO modifications to adam_server.py's own source.

Same pattern as mcp-local-authz's retrofit/ditto_retrofit.py and
retrofit/mqtt_retrofit.py: the vendor server module is imported unchanged, and both
middlewares are attached externally via FastMCP's public mcp.add_middleware() API.
Scenario 7 (zero-source-code-change retrofit) is exactly this file's existence:
adam_server.py never imports policy_engine or safety_envelope, and authz/safety-envelope
code never imports adam_server -- they are composed here, at the boundary, only.
"""

from __future__ import annotations

import fnmatch

from fastmcp import FastMCP

from ca.ca import RootCA
from policy_engine.audit_log import AuditLog
from policy_engine.middleware import LocalAuthorizationMiddleware
from policy_engine.policy import Policy

from mcp_server import adam_server
from mcp_server.safety_envelope import SafetyEnvelopeMiddleware


def _all_policy_tool_patterns(policy: Policy) -> set[str]:
    patterns: set[str] = set()
    for role_policy in policy.roles.values():
        for rule in role_policy.rules:
            patterns.update(rule.tools)
    return patterns


async def assert_policy_covers_every_adam_tool(mcp: FastMCP, policy: Policy) -> None:
    tools = await mcp.list_tools()
    actual_tool_names = {tool.name for tool in tools}
    covered_patterns = _all_policy_tool_patterns(policy)
    uncovered = {
        t for t in actual_tool_names
        if not any(fnmatch.fnmatchcase(t, p) for p in covered_patterns)
    }
    if uncovered:
        raise RuntimeError(
            "Policy coverage check failed for the adam6060 retrofit: the following "
            f"real server tools match no policy rule pattern in any role: {sorted(uncovered)}."
        )


def build_authorized_adam_server(
    *, ca: RootCA, policy: Policy, audit_log: AuditLog, adam_host: str, adam_port: int = 502,
    enable_watchdog: bool = True,
) -> tuple[FastMCP, SafetyEnvelopeMiddleware]:
    """Return the real adam6060 FastMCP server object with both middlewares attached,
    plus a handle to the SafetyEnvelopeMiddleware instance (needed by the evaluation
    harness to assert/clear E-stop and force degraded-network state directly, since
    those are LOCAL-ONLY control paths, not exposed as MCP tools -- see
    safety_envelope.py's module docstring)."""
    mcp = adam_server.mcp

    for attr in ("_mcp_local_authz_middleware", "_mcp_safety_envelope_middleware"):
        existing = getattr(mcp, attr, None)
        if existing is not None:
            middleware_list = getattr(mcp, "middleware", None)
            if middleware_list is not None and existing in middleware_list:
                middleware_list.remove(existing)
            if attr == "_mcp_safety_envelope_middleware":
                try:
                    existing.shutdown()
                except Exception:
                    pass

    authz_mw = LocalAuthorizationMiddleware(ca=ca, policy=policy, audit_log=audit_log)
    mcp.add_middleware(authz_mw)
    mcp._mcp_local_authz_middleware = authz_mw  # type: ignore[attr-defined]

    safety_mw = SafetyEnvelopeMiddleware(
        adam_host=adam_host, adam_port=adam_port, enable_watchdog=enable_watchdog
    )
    mcp.add_middleware(safety_mw)
    mcp._mcp_safety_envelope_middleware = safety_mw  # type: ignore[attr-defined]

    return mcp, safety_mw
