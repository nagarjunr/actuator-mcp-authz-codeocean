# Evaluation Results — ADAM-6060 Physical Actuation MCP Authorization + Safety Envelope

**Run date:** 2026-09-13 (UTC). **Hardware:** real Jetson Orin Nano (`rna-jetson`,
Tailscale 100.66.237.104) driving a real Advantech ADAM-6060 relay/DI module over
Modbus TCP at 10.0.0.1:502, over the Jetson's `enP8p1s0` wired interface. All scenarios
below were executed against this real hardware path — no mocking of the Modbus
transport, the relay hardware, or the digital inputs. Raw per-step JSON is in
`evaluation_results.jsonl`; the aggregated pass/fail summary is in
`evaluation_results.json`.

Code: `mcp_server/adam_server.py` (vendor MCP tool-server, zero-source-change target),
`mcp_server/safety_envelope.py` (new non-learned physical safety-envelope middleware),
`mcp_server/retrofit.py` (composition point attaching both `ca`/`policy_engine`
middleware — reused unmodified from `mcp-local-authz` — and the new safety envelope),
`mcp_server/evaluation_harness.py` (this battery's driver).

**Software note:** the evaluation ran against `fastmcp==3.4.7` (pinned to match the
version `mcp-local-authz`'s `LocalAuthorizationMiddleware._read_meta_field` was built
and tested against — a first attempt with `fastmcp==4.0.3` silently broke identity
extraction via `_meta`; downgrading fixed it and this is recorded as an honest
compatibility caveat, not something papered over).

## Summary table

| # | Scenario | Result | Real-hardware evidence |
|---|---|---|---|
| 1 | Confused-deputy relay attack rejection | **PASS** | `read-only-monitor` agent's own valid cert denied on `write_relay`; relay state unchanged before/after (all-off both times) |
| 2 | Credential replay rejection | **PASS** | 2s-TTL cert used successfully while valid, then denied 3s later (post-expiry) against the live server |
| 3 | Fail-closed on CA unreachability | **PASS** | Deleting the on-disk CA cert made `load_root_ca` raise `CertificateError`; malformed cert_b64 against the live server was denied, not allowed |
| 4 | Revocation-window timing analysis | **PASS (measurement)** | Measured: issuance→first-use 7.2–8.0 ms; worst-case exposure bound = cert TTL = 28,800s (8h, this project's default) |
| 5 | Policy tampering/signing verification under load | **PASS** | On-disk policy tampered (DENY→ALLOW) without re-signing while 20 concurrent reads were in flight; tamper detected at (re-)load via signature check; all 20 concurrent reads against the untouched in-memory policy succeeded |
| 6 | Hash-chained audit log integrity under concurrency | **PASS** | 30 concurrent mixed allow/deny calls logged; live chain verified intact (55 entries); a scratch-copy single-field edit was independently detected (`entry_hash` mismatch at seq 27) |
| 7 | Zero-source-code-change retrofit validation | **PASS** | `adam_server.py` source scanned: imports neither `policy_engine` nor `safety_envelope`; `pip show pymodbus` confirms unmodified 3.15.0 install; ADAM firmware untouched by construction |
| 8 | Baseline unauthorized-access rejection rate | **PASS** | 20/20 calls from a zero-privilege role across all 4 real tools rejected (100%) |
| 9 | Rate-limiting/duty-cycle enforcement | **PASS** | 8 rapid `write_relay` toggles on RL4: first 4 allowed, next 4 rejected by the duty-cycle rule; relay left OFF |
| 10 | State-consistency/interlock enforcement (RL0+RL2) | **PASS** | RL0 ON (real relay energized, confirmed via readback) → RL2 ON rejected while RL0 held ON → RL0 OFF → RL2 ON now allowed; both relays confirmed OFF at end |
| 11a | Envelope/limit-switch — stuck/miswired case | **PASS** | RL1 commanded ON without DI0 press; the very next RL1 command was rejected by the pending-confirmation gate (correct: models a stuck/agent-assumed-success actuator) |
| 11b | Envelope/limit-switch — correct-confirmation case | **PASS (human-attended re-run, 2026-09-13T02:26 UTC)** | Operator physically pressed DI0 during the 8s wait window; harness read `di_after_wait: [false, ...]` (pressed), `pressed_seen_during_window: true`, and the follow-up RL1 command was correctly ALLOWED |
| 12 | Emergency-stop precedence | **PASS** | E-stop asserted (local, non-network flag) → signed, policy-authorized `write_relay` to RL5 rejected, relay read back OFF → E-stop cleared → same call now succeeds, relay read back ON |
| 13a | Degraded-network fail-safe — forced-flag path | **PASS** | Forced `degraded=True` → `write_relay` rejected → middleware's own `_fail_safe_all_off()` drove all relays OFF over direct Modbus, confirmed by readback |
| 13b | Degraded-network fail-safe — real interface down/up | **PASS** | `enP8p1s0` brought down via `sudo ip link set enP8p1s0 down` (SSH-scripted, **software-simulated equivalent of a physical Ethernet disconnect**, per the task's explicit allowance — not a literal cable pull); the real background watchdog thread (independent of the forced-flag path) detected 3 consecutive missed Modbus pings and set `degraded=True` on its own; on interface recovery the watchdog cleared `degraded` and drove/confirmed all relays OFF |

**All 13 top-level scenarios completed and logged with real-hardware evidence.
14/14 individual pass/fail checks PASSED**, including scenario 11b (correct
DI0-confirmation case), which was re-run with a human operator physically
pressing the pushbutton during the 8s window (see Update below) — this closes
the one gap from the original unattended run.

## Update (2026-09-13T02:26 UTC): Scenario 11b closed
The original unattended run could not exercise the positive DI0-confirmation
path (no human available to press the button during the automated 8s window).
A standalone re-run of `scenario_11_di0_envelope_confirmation(correct_confirmation=True)`
was executed with the user physically pressing the DI0 pushbutton on cue:
`di_after_wait: [false, true, true, true, true, true]` (pressed), `pressed_seen_during_window: true`,
follow-up RL1 command `ok: true`. **14/14 checks now PASS on real hardware, zero
remaining gaps before hardware return.**

## Update (2026-09-13T02:29 UTC): Two additional coverage gaps found and closed
On review, two corner cases had never been exercised on real hardware despite
being in the wiring/tool surface:

- **RL3 authorized write**: `channel 3` previously only appeared as the target
  of a *denied* call (scenario 8, unauthorized-agent). No authorized
  `write_relay` had ever actually toggled RL3. Re-checked live: authorized
  `write_relay(3, True)` → readback confirmed ON → `write_relay(3, False)` →
  readback confirmed OFF. **PASS.**
- **`all_relays_off` authorized allow-path**: this MCP tool had only been
  exercised in the DENY direction (scenario 8's unauthorized-agent rejection).
  The actual authorized-agent → MCP-authz → Modbus allow-path for this tool
  was unconfirmed. Re-checked live: RL0+RL2 manually turned ON, then an
  authorized `all_relays_off` call correctly drove all 6 relays OFF, confirmed
  by readback. **PASS.**

Both closed with real hardware evidence in `evaluation_results.jsonl`
(`gap_fix_rl3_authorized_write`, `gap_fix_all_relays_off_authorized`). All
relays confirmed OFF after each check.

## Update (2026-09-13T02:31 UTC): Invalid-input corner case checked
One more corner case was not previously exercised: an **authorized** agent
sending an out-of-range channel number (a plausible agent bug or hallucinated
tool argument, distinct from the unauthorized-role denial tests). Checked live
against real hardware:
- `write_relay(channel=9, ...)` and `write_relay(channel=-1, ...)` from
  `operator-01` (a fully authorized role) were both cleanly rejected with a
  `ValueError` from `Adam6060`'s own bounds check (`channel must be 0-5`) --
  the MCP tool layer surfaces this as a normal tool error, not a crash.
- No relay state changed as a result of either invalid call (readback
  confirmed identical state before/after both attempts).
- The server remained healthy afterward: an immediately-following valid
  `write_relay(4, ...)` ON then OFF succeeded and was readback-confirmed.
- The audit hash chain still verified valid (103 entries, no corruption) after
  these error-path calls were logged.

**No further coverage gaps identified.** Combined with the RL3/`all_relays_off`
checks above, this covers: all 6 relay channels, all 4 tools in both
allow/deny directions, DI0 in both directions, and now malformed/out-of-range
input handling from an otherwise-authorized caller.

## Honest caveats / gaps (historical — see Updates above for resolved items)


1. **Scenario 11b (correct DI0 confirmation) not physically exercised.** The harness
   opened an 8-second window and polled DI0 for a press; no human pressed the
   pushbutton during any of the automated runs in this session, so
   `pressed_seen_during_window=False` both times it was run. The enforcement logic
   itself is verified correct in the negative direction (11a: no press → next command
   correctly blocked) and the confirmation-read code path (`_read_di_confirmation`)
   is the same code that would report `True` on an actual press — but the positive
   assertion "a real press unblocks the gate" was not independently observed on real
   hardware in this session. **Recommendation before relying on these results:** re-run
   `python -m mcp_server.evaluation_harness` on the Jetson with an operator physically
   pressing the DI0 pushbutton during the announced 8s window (the harness prints
   `waiting_for_physical_pushbutton_press` at the right moment) and confirm
   `passed: true, pressed_seen_during_window: true` for `scenario_11_di0_correct_case`
   before the hardware is returned.
2. **Scenario 13b's fail-safe write during the actual partition window necessarily
   fails** (logged as `fail_safe_all_off_failed` in the event log) — this is expected
   and honest, not a bug: while `enP8p1s0` is down, the Jetson genuinely cannot reach
   the ADAM over Modbus, so no fail-safe write can physically get there until the
   interface (or, in a real deployment, the actual network path) is restored. The
   correct claim this scenario supports is "reverts to safe-OFF as soon as the path
   is reachable again," not "instantaneous state control during a total partition" —
   the latter is a physical impossibility for any network-attached actuator and this
   report states that explicitly rather than overclaiming.
3. **RL1's motor is separately known to have a wiring/battery issue** (per
   `PLANNING_NOTES.md`), but scenario 11 only exercises the RL1 *relay contact* and
   DI0 read/write logic, not the attached motor's physical motion — the relay itself
   was independently confirmed switching correctly by direct readback in scenario 11a,
   so this caveat does not affect the validity of the safety-envelope logic tested,
   only the (out-of-scope for this middleware) mechanical motor behavior.
4. **fastmcp version pin.** `fastmcp==3.4.7` was required for correct `_meta` field
   propagation into `LocalAuthorizationMiddleware`; `fastmcp==4.0.3` (the version
   initially installed) silently broke identity extraction (`agent_cert_b64` was
   never seen by the middleware). This is recorded here as a real compatibility
   finding to be documented, not swept under the rug.
5. **Scenario 3 (fail-closed on CA unreachability)** was exercised via (a) deleting
   the on-disk CA cert file and confirming `load_root_ca` raises fail-closed, and
   (b) sending a malformed `agent_cert_b64` to the *live* server and confirming
   denial. It was NOT exercised via killing/restarting the live server process mid
   flight (that would have interrupted the whole battery run) — this is a narrower
   but still real and direct test of the same fail-closed code path.
6. **Scenario 4 is a measurement, not a pass/fail security test** — reported per
   `PLANNING_NOTES.md`'s explicit framing ("this data point turns your stated
   limitation into a quantified, defensible one instead of a hand-wave"). The 8-hour
   worst-case exposure window is this project's default `ISSUED_CERT_VALIDITY`
   inherited unmodified from `mcp-local-authz/ca/ca.py`.

## Physical safety notes

- All relay channels were confirmed at `[False]*6` (all OFF) at the end of the full
  battery run (verified via a final direct readback after the harness completed).
- Only RL0, RL1, RL2, RL4, RL5 were exercised with real writes (RL3 was not used in
  any scenario). All writes stayed within the confirmed-safe wiring described in
  `PLANNING_NOTES.md` (30VDC/1A-rated channels, DC motors / 12V bulbs already
  wired before this session).
- No new wiring was performed. The only "hardware manipulation" beyond Modbus writes
  was bringing the Jetson's `enP8p1s0` network interface down/up via SSH for scenario
  13b, exactly as explicitly pre-authorized by the task.
