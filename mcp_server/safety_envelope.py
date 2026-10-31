"""safety_envelope.py -- non-learned physical safety-envelope enforcement layer.

This is the actual novel contribution of this project beyond the mcp-local-authz authorization layer
(see PLANNING_NOTES.md). It is implemented as a SECOND FastMCP middleware, layered
UNDERNEATH policy_engine.middleware.LocalAuthorizationMiddleware in the middleware
stack (FastMCP runs middlewares in registration order for on_call_tool, each
wrapping call_next -- so whichever is added first runs "outermost"). We
deliberately register the safety envelope AFTER the authorization middleware, so a
request must first pass Ed25519 identity + policy authorization, and only then is it
subject to physical safety-envelope checks -- an unauthorized caller never even
reaches (and cannot probe) the safety-envelope's internal state. This mirrors a
real defense-in-depth industrial design: authorization decides "is this caller
allowed to try", the safety envelope decides "is this actuation physically safe to
perform right now", and neither one substitutes for the other.

Every enforcement here is a plain deterministic rule over recent state -- no ML, no
learned thresholds, consistent with the project's "non-learned physical safety
envelope" framing (PLANNING_NOTES.md's draft abstract).

Implements, in one middleware class (SafetyEnvelopeMiddleware):
  1. Rate-limiting / duty-cycle enforcement -- max N write_relay calls to the SAME
     channel within a rolling window (default: 4 cycles / 10s per channel).
  2. State-consistency / interlock enforcement -- an interlocked channel pair (e.g.
     RL0 + RL2) may never both be commanded ON; a command that would create that
     state is rejected.
  3. Envelope/limit-switch confirmation via DI0 -- after commanding a relay, the
     NEXT actuation command to the SAME channel is blocked until DI0 has been read
     back matching the expected confirmation state (or an explicit override clears
     it) -- modeling a real limit-switch/feedback-confirmation interlock.
  4. Emergency-stop precedence -- a local, non-network E-stop flag (a plain
     in-process flag flippable only via a dedicated local-only tool call, modeling a
     hardware E-stop pull-cord) always overrides and rejects ANY relay-write command
     while asserted, even one that already passed Ed25519 authorization.
  5. Degraded-network fail-safe -- a background watchdog thread pings the ADAM-6060
     on a fixed interval; if it misses N consecutive pings, it (a) sets a "degraded"
     flag that causes all further write_relay calls to be denied by this middleware,
     AND (b) proactively drives all relays OFF directly over Modbus (bypassing the
     MCP/authz path entirely, since by definition that path may be unreachable/
     degraded too) -- so the physical actuator reverts to a defined-safe state on
     its own, not by relying on a client to notice and act.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

from mcp_server.adam6060 import Adam6060

logger = logging.getLogger(__name__)

INTERLOCKED_PAIR = (0, 2)  # RL0 <-> RL2, per PLANNING_NOTES.md scenario 10
DUTY_CYCLE_WINDOW_S = 10.0
DUTY_CYCLE_MAX_CYCLES = 4  # max write_relay calls to one channel per window
# The relay CHANNEL whose actuations require DI0 feedback confirmation before the
# next command to that same channel is authorized (scenario 11). Deliberately a
# DIFFERENT channel than the INTERLOCKED_PAIR (0, 2) above -- RL0 is needed
# unencumbered for the interlock scenario, so RL1 (relay confirmed good, per
# PLANNING_NOTES.md hardware notes -- only its attached motor has an unrelated
# wiring issue, irrelevant to exercising the relay/DI0-gate logic itself) is used
# for the envelope/limit-switch-confirmation scenario instead. DI0 itself (the
# physical digital input read) is unchanged -- only which relay channel's command
# sequence is gated by it.
ENVELOPE_GATED_CHANNEL = 1
DI_CONFIRM_CHANNEL = 0  # DI0, the physical digital input read for confirmation
WATCHDOG_INTERVAL_S = 1.0
WATCHDOG_MISS_THRESHOLD = 3  # consecutive missed pings -> degraded


class SafetyEnvelopeDeniedError(ToolError):
    """Raised when a tool call is blocked by the physical safety-envelope layer
    (as distinct from AuthorizationDeniedError, which is the identity/policy layer).
    Kept as a separate exception type so evaluation scripts and logs can tell
    apart *which* layer produced a given denial -- important for this project's
    evaluation, which needs to attribute failures to the correct enforcement
    mechanism (scenarios 9-13 specifically test THIS layer, not the authz layer)."""


@dataclass
class _ChannelState:
    recent_commands: deque = field(default_factory=lambda: deque())
    pending_confirmation: bool = False
    expected_di_state: bool | None = None
    last_commanded_value: bool | None = None


class SafetyEnvelopeMiddleware(Middleware):
    def __init__(self, *, adam_host: str, adam_port: int = 502, enable_watchdog: bool = True) -> None:
        self._adam_host = adam_host
        self._adam_port = adam_port
        self._lock = threading.Lock()
        self._channel_state: dict[int, _ChannelState] = {}
        self._estop_asserted = False
        self._degraded = False
        self._consecutive_watchdog_misses = 0
        self._watchdog_stop = threading.Event()
        self._watchdog_thread: threading.Thread | None = None
        self._event_log: list[dict[str, Any]] = []
        if enable_watchdog:
            self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
            self._watchdog_thread.start()

    # ---- test/eval control surface (not exposed as MCP tools; called directly by
    # the evaluation harness over the same in-process object, modeling a local
    # hardware E-stop pull-cord / operator panel that is NOT reachable via the
    # network/MCP path at all) ----
    def assert_estop(self) -> None:
        with self._lock:
            self._estop_asserted = True
            self._log_event("estop_asserted", {})

    def clear_estop(self) -> None:
        with self._lock:
            self._estop_asserted = False
            self._log_event("estop_cleared", {})

    def is_degraded(self) -> bool:
        with self._lock:
            return self._degraded

    def force_degraded_for_test(self, degraded: bool) -> None:
        """Test-only hook: directly force the degraded flag without waiting for the
        real watchdog interval, used by the evaluation harness's network-partition
        scenario to get a deterministic, fast test while the REAL watchdog thread
        (see _watchdog_loop) is what actually detects it independently in real time
        too -- both are exercised and logged, see results/evaluation_results.md
        scenario 13 for which measurement is which."""
        with self._lock:
            self._degraded = degraded
            self._log_event("force_degraded_for_test", {"degraded": degraded})

    def get_event_log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._event_log)

    def shutdown(self) -> None:
        self._watchdog_stop.set()
        if self._watchdog_thread is not None:
            self._watchdog_thread.join(timeout=5)

    def _log_event(self, kind: str, detail: dict[str, Any]) -> None:
        self._event_log.append({"ts": time.time(), "kind": kind, "detail": detail})

    def _channel(self, ch: int) -> _ChannelState:
        if ch not in self._channel_state:
            self._channel_state[ch] = _ChannelState()
        return self._channel_state[ch]

    # ---- watchdog: real, continuous Modbus reachability check against the real
    # ADAM-6060, independent of whatever tool calls are or aren't happening ----
    def _watchdog_loop(self) -> None:
        while not self._watchdog_stop.wait(WATCHDOG_INTERVAL_S):
            ok = False
            try:
                with Adam6060(self._adam_host, self._adam_port, timeout=1.0) as adam:
                    adam.read_relays()
                ok = True
            except Exception as e:
                logger.warning("watchdog: ADAM-6060 unreachable: %s", e)

            with self._lock:
                if ok:
                    self._consecutive_watchdog_misses = 0
                    if self._degraded:
                        self._degraded = False
                        self._log_event("watchdog_recovered", {})
                else:
                    self._consecutive_watchdog_misses += 1
                    if (
                        self._consecutive_watchdog_misses >= WATCHDOG_MISS_THRESHOLD
                        and not self._degraded
                    ):
                        self._degraded = True
                        self._log_event(
                            "watchdog_degraded",
                            {"consecutive_misses": self._consecutive_watchdog_misses},
                        )

            if self.is_degraded():
                self._fail_safe_all_off()

    def _fail_safe_all_off(self) -> None:
        """Drive every relay OFF directly over Modbus, bypassing the MCP/authz path
        entirely -- this is the actual fail-safe action for scenario 13. Best-effort:
        if the ADAM is genuinely unreachable this will also fail, which is the
        expected/honest outcome during a real network partition (logged, not
        swallowed) -- the guarantee this design provides is "revert to safe state as
        soon as the path is reachable again", not "instantaneously force state
        during a total partition", which is a physical impossibility for any
        network-attached actuator and must be stated honestly."""
        try:
            with Adam6060(self._adam_host, self._adam_port, timeout=1.0) as adam:
                adam.all_relays_off()
            self._log_event("fail_safe_all_off_succeeded", {})
        except Exception as e:
            self._log_event("fail_safe_all_off_failed", {"error": str(e)})

    # ---- the actual middleware hook ----
    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: Callable[[MiddlewareContext[mt.CallToolRequestParams]], Awaitable[ToolResult]],
    ) -> ToolResult:
        tool_name = context.message.name
        arguments = context.message.arguments or {}

        try:
            if tool_name == "write_relay":
                channel = int(arguments.get("channel"))
                value = bool(arguments.get("value"))
                self._check_write_relay(channel, value)
            # read tools / all_relays_off are always allowed through the safety
            # envelope layer (all_relays_off is itself a safe action, never blocked)
        except SafetyEnvelopeDeniedError:
            self._log_event(
                "safety_envelope_denied", {"tool": tool_name, "arguments": arguments}
            )
            raise
        except Exception as e:
            # fail-closed: any bug in this layer must also deny, consistent with the
            # authorization middleware's own fail-closed guarantee (defense in depth
            # applies to this layer's own robustness too, not just to the authz layer)
            logger.error("Safety envelope failed closed for tool %r: %s", tool_name, e)
            raise SafetyEnvelopeDeniedError(
                f"Tool '{tool_name}' denied by safety envelope: internal error "
                f"({type(e).__name__}) -- failing closed."
            ) from e

        result = await call_next(context)

        if tool_name == "write_relay":
            channel = int(arguments.get("channel"))
            value = bool(arguments.get("value"))
            with self._lock:
                ch_state = self._channel(channel)
                ch_state.last_commanded_value = value
                ch_state.pending_confirmation = True
                ch_state.expected_di_state = value

        return result

    def _check_write_relay(self, channel: int, value: bool) -> None:
        with self._lock:
            # 4. E-stop precedence -- checked first, always wins.
            if self._estop_asserted:
                raise SafetyEnvelopeDeniedError(
                    "write_relay denied: local emergency-stop is asserted and takes "
                    "precedence over any signed remote command."
                )

            # 5. Degraded-network fail-safe -- no new commands while degraded.
            if self._degraded:
                raise SafetyEnvelopeDeniedError(
                    "write_relay denied: safety envelope is in a degraded-network "
                    "state (ADAM-6060 watchdog missed too many consecutive pings); "
                    "actuator has been driven to safe OFF and will not accept new "
                    "commands until connectivity is confirmed restored."
                )

            # 2. State-consistency / interlock enforcement.
            if value and channel in INTERLOCKED_PAIR:
                other = INTERLOCKED_PAIR[1] if channel == INTERLOCKED_PAIR[0] else INTERLOCKED_PAIR[0]
                other_state = self._channel(other)
                if other_state.last_commanded_value is True:
                    raise SafetyEnvelopeDeniedError(
                        f"write_relay denied: channel {channel} is interlocked with "
                        f"channel {other}, which is currently commanded ON -- "
                        "refusing to create a simultaneous-conflicting-ON state."
                    )

            # 1. Rate-limiting / duty-cycle enforcement.
            ch_state = self._channel(channel)
            now = time.monotonic()
            while ch_state.recent_commands and now - ch_state.recent_commands[0] > DUTY_CYCLE_WINDOW_S:
                ch_state.recent_commands.popleft()
            if len(ch_state.recent_commands) >= DUTY_CYCLE_MAX_CYCLES:
                raise SafetyEnvelopeDeniedError(
                    f"write_relay denied: channel {channel} has already been "
                    f"commanded {len(ch_state.recent_commands)} times in the last "
                    f"{DUTY_CYCLE_WINDOW_S}s (max {DUTY_CYCLE_MAX_CYCLES}) -- "
                    "rate-limit/duty-cycle protection against excessive relay "
                    "cycling."
                )
            ch_state.recent_commands.append(now)

            # 3. Envelope/limit-switch confirmation via DI0.
            #    Only enforced for ENVELOPE_GATED_CHANNEL (RL1) -- for all other
            #    channels there is no DI0-confirmation requirement configured, so
            #    this check is a no-op for them (stated explicitly, not silently
            #    assumed; see ENVELOPE_GATED_CHANNEL's docstring above for why RL1
            #    specifically, not RL0, is used for this gate).
            if channel == ENVELOPE_GATED_CHANNEL and ch_state.pending_confirmation:
                confirmed = self._read_di_confirmation(ch_state.expected_di_state)
                if not confirmed:
                    raise SafetyEnvelopeDeniedError(
                        f"write_relay denied: channel {channel}'s previous commanded "
                        f"state ({ch_state.expected_di_state}) was not confirmed via "
                        "DI0 feedback before this next actuation was requested -- "
                        "possible stuck/miswired actuator or agent-assumed-success "
                        "condition."
                    )
                ch_state.pending_confirmation = False

    def _read_di_confirmation(self, expected: bool | None) -> bool:
        """Read DI0 directly (bypassing the tool-call path, since this is an internal
        safety check, not itself an authorized/audited tool call) and compare against
        the expected confirmation state. NOTE (honest scope note, see
        results/evaluation_results.md scenario 11): DI0 in this rig is wired to a
        momentary pushbutton, not a mechanically-coupled limit switch on the relay
        itself -- so genuine confirmation requires a human/operator to press the
        button in the physical-loop test, or the check will correctly report
        not-confirmed. This models a limit-switch confirmation gate; it does not
        simulate an automatic limit switch that doesn't exist on this rig."""
        try:
            with Adam6060(self._adam_host, self._adam_port, timeout=1.0) as adam:
                di_state = adam.read_digital_inputs()
            di0 = di_state[DI_CONFIRM_CHANNEL]
            # Dry-contact convention (per adam6060.py docstring): True=open (not
            # pressed), False=closed/pressed. We treat "pressed" (False) as the
            # confirmation signal that an operator acknowledged the actuation,
            # regardless of the commanded relay value's own polarity -- this models
            # a confirm-button pattern (operator confirms the physical result),
            # which is what is actually wired on this rig (see PLANNING_NOTES.md's
              # "DI0 pushbutton confirmed working" hardware note).
            return di0 is False
        except Exception as e:
            logger.warning("DI0 confirmation read failed: %s", e)
            return False
