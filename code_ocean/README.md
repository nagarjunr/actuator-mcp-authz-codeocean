# Code Ocean Capsule — actuator-mcp-authz

Reproducibility capsule for actuator-mcp-authz: a non-learned physical safety envelope for industrial relay and digital I/O control.

## Honest scope note (read this first)

Unlike the companion capsule for `mcp-local-authz` , where 66 of 77
tests are fully self-contained (in-process fake servers, no external
dependency), **this project's evaluation is a hardware-in-the-loop battery
against a real Advantech ADAM-6060 industrial relay/digital-I/O module**
reachable only over a private Modbus TCP network segment. There is no mock
or simulated ADAM-6060 in this codebase, and we do not fabricate one for this
capsule: doing so would silently misrepresent what was actually validated (a
real physical relay switching a real motor and bulb, and a real pushbutton
providing digital-input feedback), which is the entire point of this project's
evaluation methodology.

**What this capsule verifies (no hardware required):**
- The authorization layer (`ca/`, `policy_engine/`) is imported and used
  **unmodified** from `mcp-local-authz` -- static import/module inspection.
- `mcp_server/adam_server.py` (the vendor-facing tool-server module) imports
  neither `policy_engine` nor `mcp_server.safety_envelope`, confirming the
  zero-source-change retrofit property this project claims (scenario 7).
- All Python modules import cleanly and pass static/syntax checks with the
  pinned dependency versions (notably `fastmcp==3.4.7` -- this exact pin matters: `fastmcp==4.0.3` silently
  breaks identity-metadata propagation into the authorization middleware,
  a real compatibility defect this project's development discovered).

**What this capsule does NOT and cannot reproduce:**
- Any of the 13 evaluation scenarios / 18 individual pass/fail checks
  reported in this project's evaluation, all of which require a live ADAM-6060 on a reachable
  Modbus TCP endpoint, real relay-driven loads (a DC motor, a 12V bulb), and
  for one scenario (11b) a human physically pressing a wired pushbutton.
  These results are reported in `results/evaluation_results.md` /
  `.json` / `.jsonl` as an evidentiary record of what was actually run on
  real hardware (an NVIDIA Jetson Orin Nano driving a real ADAM-6060), not as
  something this capsule re-executes.

To actually reproduce the full hardware evaluation, you need the physical
rig described in the project's Retrofit Methodology notes and
`hardware/assembly_guide.pdf` (full repo, not this capsule):

```bash
git clone https://github.com/nagarjunr/actuator-mcp-authz.git
cd actuator-mcp-authz
uv sync
uv run python -m mcp_server.setup_ca_and_policy   # one-time: generate CA/certs/signed policy
# edit ADAM_HOST in mcp_server/evaluation_harness.py to your module's real IP
uv run python -m mcp_server.evaluation_harness
```

## What `run` does in this capsule

```bash
uv sync --frozen --no-cache
uv run python -m code_ocean.verify_static_properties
```

Verifies the zero-source-change property and confirms all modules import
cleanly with the pinned dependencies, with output logged to `/results`.
Auto-detects the project root at runtime (checks `/code` first, matching
Code Ocean's convention).
