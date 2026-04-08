"""
cpsforge.plc.modbus_client
===========================
PlcBackend implementation for Modbus TCP PLCs (OpenPLC, Codesys, etc.).

Uses pymodbus to communicate with any Modbus TCP server.  OpenPLC v4
maps IEC 61131-3 located variables to Modbus addresses according to the
standard OpenPLC addressing scheme:

  %IX0.0 .. %IX99.7  →  Discrete Inputs   (addr 0-799)
  %QX0.0 .. %QX99.7  →  Coils             (addr 0-799)
  %IW0   .. %IW1023   →  Input Registers    (addr 0-1023)
  %QW0   .. %QW1023   →  Holding Registers  (addr 0-1023)

Tag addresses in scene YAMLs for Modbus scenes use the notation:

  COIL<n>            → Coil (single bit, read/write)
  DI<n>              → Discrete Input (single bit, read-only)
  HR<n>              → Holding Register (16-bit word, read/write)
  IR<n>              → Input Register (16-bit word, read-only)
  HR<n>,FLOAT        → Two consecutive holding registers as IEEE 754 float
  IR<n>,FLOAT        → Two consecutive input registers as IEEE 754 float

These are parsed by :func:`parse_modbus_address`.
"""

from __future__ import annotations

import logging
import re
import struct
import time
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional

from cpsforge.core.models import TagDefinition
from cpsforge.plc.backend import PlcBackend

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Modbus address model
# ---------------------------------------------------------------------------


class ModbusRegion(str, Enum):
    COIL = "coil"                    # %QX — read/write single bit
    DISCRETE_INPUT = "discrete"      # %IX — read-only single bit
    HOLDING_REGISTER = "holding"     # %QW — read/write 16-bit
    INPUT_REGISTER = "input"         # %IW — read-only 16-bit


@dataclass
class ModbusAddress:
    """Parsed Modbus address for one tag."""
    region: ModbusRegion
    address: int          # Register or coil number
    is_float: bool        # If True, read 2 consecutive registers as IEEE 754

    @property
    def count(self) -> int:
        """Number of registers/coils to read."""
        if self.region in (ModbusRegion.COIL, ModbusRegion.DISCRETE_INPUT):
            return 1
        return 2 if self.is_float else 1


_RE_COIL = re.compile(r"^COIL(\d+)$", re.IGNORECASE)
_RE_DI = re.compile(r"^DI(\d+)$", re.IGNORECASE)
_RE_HR = re.compile(r"^HR(\d+)(?:,FLOAT)?$", re.IGNORECASE)
_RE_IR = re.compile(r"^IR(\d+)(?:,FLOAT)?$", re.IGNORECASE)


def parse_modbus_address(address: str) -> ModbusAddress:
    """
    Parse a CPSForge Modbus tag address into a :class:`ModbusAddress`.

    Raises ValueError if the format is unrecognized.
    """
    addr = address.strip()

    m = _RE_COIL.match(addr)
    if m:
        return ModbusAddress(ModbusRegion.COIL, int(m.group(1)), False)

    m = _RE_DI.match(addr)
    if m:
        return ModbusAddress(ModbusRegion.DISCRETE_INPUT, int(m.group(1)), False)

    m = _RE_HR.match(addr)
    if m:
        is_float = ",FLOAT" in addr.upper()
        return ModbusAddress(ModbusRegion.HOLDING_REGISTER, int(m.group(1)), is_float)

    m = _RE_IR.match(addr)
    if m:
        is_float = ",FLOAT" in addr.upper()
        return ModbusAddress(ModbusRegion.INPUT_REGISTER, int(m.group(1)), is_float)

    raise ValueError(
        f"Cannot parse Modbus address '{address}'. "
        "Expected: COIL<n>, DI<n>, HR<n>, HR<n>,FLOAT, IR<n>, IR<n>,FLOAT"
    )


# ---------------------------------------------------------------------------
# Value encoding / decoding for Modbus registers
# ---------------------------------------------------------------------------


def _decode_modbus(registers: list, maddr: ModbusAddress) -> Any:
    """Decode register values to Python type."""
    if maddr.region in (ModbusRegion.COIL, ModbusRegion.DISCRETE_INPUT):
        return bool(registers[0])
    if maddr.is_float:
        # Two registers → 4 bytes → IEEE 754 float (big-endian)
        raw = struct.pack(">HH", registers[0], registers[1])
        return struct.unpack(">f", raw)[0]
    return registers[0]


def _encode_modbus(value: Any, maddr: ModbusAddress) -> list:
    """Encode a Python value to Modbus register list."""
    if maddr.region == ModbusRegion.COIL:
        return [bool(value)]
    if maddr.is_float:
        raw = struct.pack(">f", float(value))
        hi, lo = struct.unpack(">HH", raw)
        return [hi, lo]
    return [int(value) & 0xFFFF]


# ---------------------------------------------------------------------------
# Modbus PLC configuration
# ---------------------------------------------------------------------------


class ModbusConfig:
    """
    Configuration for a Modbus TCP PLC connection.

    Can be constructed from a dict (YAML) or directly.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 502,
        unit_id: int = 1,
        connect_timeout_s: float = 5.0,
        poll_interval_ms: int = 500,
        reconnect_attempts: int = 3,
        reconnect_delay_s: float = 2.0,
        live_writes_enabled: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.connect_timeout_s = connect_timeout_s
        self.poll_interval_ms = poll_interval_ms
        self.reconnect_attempts = reconnect_attempts
        self.reconnect_delay_s = reconnect_delay_s
        self.live_writes_enabled = live_writes_enabled

    @classmethod
    def from_dict(cls, data: dict) -> "ModbusConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__init__.__code__.co_varnames})


# ---------------------------------------------------------------------------
# ModbusClient
# ---------------------------------------------------------------------------


class ModbusClient(PlcBackend):
    """
    PlcBackend implementation for Modbus TCP PLCs.

    Uses pymodbus (>=3.0) for communication.  Suitable for OpenPLC v4
    and any other Modbus TCP server.

    Parameters
    ----------
    config:
        :class:`ModbusConfig` with connection details.
    event_logger:
        Optional PlcEventLogger for structured event capture.
    """

    def __init__(self, config: ModbusConfig, event_logger=None) -> None:
        self._config = config
        self._lock = Lock()
        self._client = None        # pymodbus.client.ModbusTcpClient
        self._connected: bool = False
        self._event_logger = event_logger

    # ------------------------------------------------------------------
    # Lazy pymodbus import
    # ------------------------------------------------------------------

    @staticmethod
    def _get_pymodbus():
        try:
            from pymodbus.client import ModbusTcpClient
            return ModbusTcpClient
        except ImportError as exc:
            raise ImportError(
                "pymodbus is not installed. "
                "Install it with: pip install pymodbus>=3.0"
            ) from exc

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        ModbusTcpClient = self._get_pymodbus()
        with self._lock:
            if self._connected:
                return
            self._client = ModbusTcpClient(
                host=self._config.host,
                port=self._config.port,
                timeout=self._config.connect_timeout_s,
            )
            last_exc: Optional[Exception] = None
            for attempt in range(1, self._config.reconnect_attempts + 2):
                try:
                    logger.info(
                        "Connecting to Modbus PLC at %s:%d — attempt %d",
                        self._config.host, self._config.port, attempt,
                    )
                    connected = self._client.connect()
                    if connected:
                        self._connected = True
                        logger.info("Modbus PLC connected: %s:%d",
                                    self._config.host, self._config.port)
                        if self._event_logger:
                            self._event_logger.log_connect(
                                f"{self._config.host}:{self._config.port}")
                        return
                    raise ConnectionError("connect() returned False")
                except Exception as exc:
                    last_exc = exc
                    logger.warning("Modbus connection attempt %d failed: %s",
                                   attempt, exc)
                    if attempt <= self._config.reconnect_attempts:
                        time.sleep(self._config.reconnect_delay_s)
            from cpsforge.plc.client import PLCConnectionError
            raise PLCConnectionError(
                f"Could not connect to Modbus PLC at "
                f"{self._config.host}:{self._config.port} "
                f"after {self._config.reconnect_attempts + 1} attempts: {last_exc}"
            )

    def disconnect(self) -> None:
        with self._lock:
            if self._client is not None and self._connected:
                try:
                    self._client.close()
                    logger.info("Modbus PLC disconnected.")
                    if self._event_logger:
                        self._event_logger.log_disconnect()
                except Exception as exc:
                    logger.warning("Error during Modbus disconnect: %s", exc)
            self._connected = False
            self._client = None

    def is_connected(self) -> bool:
        with self._lock:
            if not self._connected or self._client is None:
                return False
            return self._client.connected

    def health_check(self) -> bool:
        with self._lock:
            if not self._connected or self._client is None:
                return False
            try:
                # Read coil 0 as a lightweight check
                result = self._client.read_coils(0, count=1, device_id=self._config.unit_id)
                return not result.isError()
            except Exception:
                return False

    def _ensure_connected(self) -> None:
        if not self.is_connected():
            logger.info("Modbus connection lost — attempting reconnect.")
            self._connected = False
            self.connect()

    # ------------------------------------------------------------------
    # Tag I/O
    # ------------------------------------------------------------------

    def read_tag(self, tag: TagDefinition) -> Optional[Any]:
        self._ensure_connected()
        maddr = parse_modbus_address(tag.address)
        with self._lock:
            try:
                result = self._read_region(maddr)
                if result is None:
                    return None
                value = _decode_modbus(result, maddr)
                if value is not None and tag.scale is not None:
                    value = value * tag.scale
                return value
            except Exception as exc:
                logger.warning("Modbus read error for %s (%s): %s",
                               tag.name, tag.address, exc)
                return None

    def read_many(self, tags: List[TagDefinition]) -> Dict[str, Optional[Any]]:
        self._ensure_connected()
        results: Dict[str, Optional[Any]] = {}
        for tag in tags:
            results[tag.name] = self.read_tag(tag)
        if self._event_logger:
            self._event_logger.log_poll(self._current_step, results)
        return results

    def write_tag(self, tag: TagDefinition, value: Any) -> bool:
        if not self._config.live_writes_enabled:
            from cpsforge.plc.client import SafetyError
            raise SafetyError(
                "Live writes are disabled (live_writes_enabled=False). "
                "Set live_writes_enabled=True in the Modbus config."
            )
        self._ensure_connected()
        if tag.scale is not None:
            value = round(value / tag.scale)
        maddr = parse_modbus_address(tag.address)
        encoded = _encode_modbus(value, maddr)
        with self._lock:
            try:
                success = self._write_region(maddr, encoded)
                if success:
                    logger.debug("Modbus write: %s = %s", tag.name, value)
                    if self._event_logger:
                        self._event_logger.log_write(
                            step_id=self._current_step,
                            tag_name=tag.name,
                            address_str=tag.address,
                            written_value=value,
                        )
                return success
            except Exception as exc:
                logger.error("Modbus write error for %s (%s): %s",
                             tag.name, tag.address, exc)
                return False

    # ------------------------------------------------------------------
    # Internal Modbus region helpers
    # ------------------------------------------------------------------

    def _read_region(self, maddr: ModbusAddress) -> Optional[list]:
        """Read from the appropriate Modbus region. Returns raw register list."""
        uid = self._config.unit_id
        if maddr.region == ModbusRegion.COIL:
            r = self._client.read_coils(maddr.address, count=1, device_id=uid)
            return r.bits[:1] if not r.isError() else None
        elif maddr.region == ModbusRegion.DISCRETE_INPUT:
            r = self._client.read_discrete_inputs(maddr.address, count=1, device_id=uid)
            return r.bits[:1] if not r.isError() else None
        elif maddr.region == ModbusRegion.HOLDING_REGISTER:
            r = self._client.read_holding_registers(
                maddr.address, count=maddr.count, device_id=uid)
            return r.registers if not r.isError() else None
        elif maddr.region == ModbusRegion.INPUT_REGISTER:
            r = self._client.read_input_registers(
                maddr.address, count=maddr.count, device_id=uid)
            return r.registers if not r.isError() else None
        return None

    def _write_region(self, maddr: ModbusAddress, values: list) -> bool:
        """Write to the appropriate Modbus region. Returns True on success."""
        uid = self._config.unit_id
        if maddr.region == ModbusRegion.COIL:
            r = self._client.write_coil(maddr.address, values[0], device_id=uid)
            return not r.isError()
        elif maddr.region == ModbusRegion.HOLDING_REGISTER:
            if maddr.is_float:
                r = self._client.write_registers(
                    maddr.address, values, device_id=uid)
            else:
                r = self._client.write_register(
                    maddr.address, values[0], device_id=uid)
            return not r.isError()
        elif maddr.region in (ModbusRegion.DISCRETE_INPUT,
                              ModbusRegion.INPUT_REGISTER):
            logger.error("Cannot write to read-only Modbus region: %s",
                         maddr.region)
            return False
        return False
