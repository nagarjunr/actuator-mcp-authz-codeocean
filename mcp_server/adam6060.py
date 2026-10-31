"""adam6060.py -- copy of the verified bring-up wrapper (hardware/jetson_src/adam6060.py),
re-hosted inside the actual MCP-server project so the server has no import dependency on
the throwaway bring-up directory. Register addresses/behavior unchanged and still carry
the same confirmed-on-real-hardware provenance documented in
the project's hardware bring-up log.
"""

from __future__ import annotations

from dataclasses import dataclass

from pymodbus.client import ModbusTcpClient

DI_BASE_ADDRESS = 0
DO_BASE_ADDRESS = 16
NUM_CHANNELS = 6


@dataclass
class Adam6060:
    host: str
    port: int = 502
    timeout: float = 3.0

    def __post_init__(self) -> None:
        self._client = ModbusTcpClient(self.host, port=self.port, timeout=self.timeout)

    def __enter__(self) -> "Adam6060":
        if not self._client.connect():
            raise ConnectionError(
                f"Could not connect to ADAM-6060 at {self.host}:{self.port}."
            )
        return self

    def __exit__(self, *exc_info) -> None:
        self._client.close()

    def read_digital_inputs(self) -> list[bool]:
        result = self._client.read_discrete_inputs(address=DI_BASE_ADDRESS, count=NUM_CHANNELS)
        if result.isError():
            raise IOError(f"Modbus error reading digital inputs: {result}")
        return list(result.bits[:NUM_CHANNELS])

    def read_relays(self) -> list[bool]:
        result = self._client.read_coils(address=DO_BASE_ADDRESS, count=NUM_CHANNELS)
        if result.isError():
            raise IOError(f"Modbus error reading relay coils: {result}")
        return list(result.bits[:NUM_CHANNELS])

    def write_relay(self, channel: int, value: bool) -> None:
        if not 0 <= channel < NUM_CHANNELS:
            raise ValueError(f"channel must be 0-{NUM_CHANNELS - 1}, got {channel}")
        result = self._client.write_coil(address=DO_BASE_ADDRESS + channel, value=value)
        if result.isError():
            raise IOError(f"Modbus error writing relay {channel}={value}: {result}")

    def write_all_relays(self, values: list[bool]) -> None:
        if len(values) != NUM_CHANNELS:
            raise ValueError(f"expected {NUM_CHANNELS} values, got {len(values)}")
        result = self._client.write_coils(address=DO_BASE_ADDRESS, values=values)
        if result.isError():
            raise IOError(f"Modbus error writing all relays {values}: {result}")

    def all_relays_off(self) -> None:
        self.write_all_relays([False] * NUM_CHANNELS)
