"""adam_server.py -- the "vendor" MCP tool-server exposing the ADAM-6060's Modbus TCP
interface as MCP tools. This file is the zero-source-change-retrofit target: per
scenario 7 of the evaluation battery, this file is written ONCE and never modified
again to add authorization or the safety envelope -- both are attached externally
(see retrofit.py), exactly the same pattern mcp-local-authz uses for its Eclipse
Ditto and MQTT retrofit targets (retrofit/ditto_retrofit.py, retrofit/mqtt_retrofit.py).

Design note: pymodbus itself is also completely unmodified (installed straight from
PyPI, 3.15.0) and the ADAM-6060's own firmware is obviously untouched -- the "zero
source change" claim in this project covers both the vendor MCP wrapper AND the
underlying protocol stack/firmware, not just the wrapper file.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

from mcp_server.adam6060 import Adam6060

ADAM_HOST = os.environ.get("ADAM6060_HOST", "10.0.0.1")
ADAM_PORT = int(os.environ.get("ADAM6060_PORT", "502"))

mcp = FastMCP("adam6060-actuator-server")


@mcp.tool()
def read_digital_inputs() -> list[bool]:
    """Read all 6 digital inputs (DI0-DI5) from the ADAM-6060. True=open, False=closed/pressed."""
    with Adam6060(ADAM_HOST, ADAM_PORT) as adam:
        return adam.read_digital_inputs()


@mcp.tool()
def read_relays() -> list[bool]:
    """Read all 6 relay/coil states (DO0-DO5) from the ADAM-6060. True=energized/closed."""
    with Adam6060(ADAM_HOST, ADAM_PORT) as adam:
        return adam.read_relays()


@mcp.tool()
def write_relay(channel: int, value: bool) -> dict:
    """Set a single relay channel (0-5) on (True) or off (False)."""
    with Adam6060(ADAM_HOST, ADAM_PORT) as adam:
        adam.write_relay(channel, value)
        state = adam.read_relays()
    return {"channel": channel, "commanded": value, "relay_state_after": state}


@mcp.tool()
def all_relays_off() -> dict:
    """De-energize every relay channel (safe default state)."""
    with Adam6060(ADAM_HOST, ADAM_PORT) as adam:
        adam.all_relays_off()
        state = adam.read_relays()
    return {"relay_state_after": state}
