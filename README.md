# actuator-mcp-authz

Physical-actuation extension of `mcp-local-authz`'s control-plane-optional
MCP authorization architecture, plus a new non-learned physical
safety-envelope middleware. Implementation of a non-learned safety envelope for industrial relay and digital I/O control.

## What this is

The prior project (`mcp-local-authz`) established locally-rooted PKI, a signed
declarative policy, protocol-native middleware enforcement, and a
hash-chained audit log for MCP tool-servers exposing *information* tools
(Eclipse Ditto, MQTT). That architecture answers "is this agent permitted to
call this tool" -- it says nothing about whether an authorized command is
physically safe to *execute*.

This project retrofits that authorization stack, **unmodified**, onto a new
MCP tool-server wrapping a real industrial actuator: an Advantech ADAM-6060
(6-channel relay output, 6-channel digital input) over Modbus TCP. Underneath
the unchanged authorization middleware, it adds a second FastMCP middleware
implementing five non-learned physical safety rules: rate-limiting/duty-cycle
enforcement, interlock/state-consistency enforcement, limit-switch/digital-input
confirmation, local emergency-stop precedence, and degraded-network fail-safe
reversion.

## Status

Implementation complete, verified end-to-end on real hardware (NVIDIA Jetson
Orin Nano driving a real ADAM-6060, a real DC motor, a real 12V bulb, and a
real pushbutton digital input). All 18 individual pass/fail checks (13
scenarios, 14 sub-checks, plus 4 corner cases found in a post-hoc coverage
review) passed against the real, live rig -- see `results/evaluation_results.md`
for the full evidence log.

- `ca/`, `policy_engine/` -- reused **unmodified** from `mcp-local-authz`
  (locally-rooted Ed25519 CA, signed policy engine, hash-chained audit log,
  FastMCP authorization middleware)
- `mcp_server/adam6060.py` -- thin Modbus TCP wrapper around the ADAM-6060
  (read digital inputs, read/write relays), the "vendor" device driver
- `mcp_server/adam_server.py` -- the MCP tool-server itself; imports neither
  `policy_engine` nor `safety_envelope`, confirming the zero-source-change
  retrofit property
- `mcp_server/safety_envelope.py` -- the new non-learned physical
  safety-envelope middleware (this project's actual novel contribution)
- `mcp_server/retrofit.py` -- composes both middleware layers onto the vendor
  server via the host framework's own public extension point
- `mcp_server/setup_ca_and_policy.py` -- one-time commissioning script:
  generates a fresh root CA, issues agent certs, signs the policy document
- `mcp_server/evaluation_harness.py` -- the 13-scenario / 14-check evaluation
  battery, run for real against live hardware
- `hardware/assembly_guide.tex` (+ compiled `.pdf`) -- full physical bring-up
  guide, corrected against the actual unit's terminal labels (including the
  Iso.GND digital-input-ground gotcha discovered during bring-up)
- `results/` -- full evaluation evidence: `evaluation_results.md` (narrative +
  table), `evaluation_results.json` / `.jsonl` (structured/raw logs),
  `evidence_snapshot/` (sanitized runtime artifacts: signed policy, root CA
  **certificate only**, issued agent certificates, hash-chained audit logs --
  no private keys are committed; regenerate a fresh CA and certs locally via
  `mcp_server/setup_ca_and_policy.py` to reproduce)

## Running the evaluation yourself

Requires a real ADAM-6060 (or compatible Modbus TCP relay/DI module) reachable
on the network; this is a hardware-in-the-loop evaluation, not a mocked test
suite.

```bash
uv sync
uv run python -m mcp_server.setup_ca_and_policy   # one-time: generate CA, certs, signed policy
uv run python -m mcp_server.evaluation_harness    # runs all 13 scenarios against live hardware
```

Edit `ADAM_HOST` in `mcp_server/evaluation_harness.py` to point at your own
module's IP. Scenario 11b (the positive DI0-confirmation case) requires a
human to physically press the wired pushbutton during an announced 8-second
window -- see the project's Evaluation notes for why this is reported as a
single human-attended trial rather than a fully automated result.

## License

MIT.
