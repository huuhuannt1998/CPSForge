"""
CPSForge Real PLC Client
=========================
Wraps python-snap7 to provide a clean, typed interface for reading and writing
Siemens S7 PLC tags.

Design principles:
  - This client implements the PlcBackend interface for Siemens S7 PLCs.
  - All WRITE operations are gated by the PlcClient.live_writes_enabled flag.
    If the flag is False (default), write_tag() raises a SafetyError.
  - Callers outside this module (attackers, orchestrators) must use the
    shielded write path in cpsforge.shield -- never call _raw_write() directly.
  - Connection errors are non-fatal during polling; they produce a log entry
    and a None return value, and trigger reconnect logic.
"""

from __future__ import annotations

import logging
import struct
import time
from threading import Lock
from typing import Any, Dict, List, Optional, Union

from cpsforge.core.config import PLCConfig
from cpsforge.core.models import TagDefinition, DataType
from cpsforge.plc.address import parse_address, S7Area, S7WordLen, S7Address
from cpsforge.plc.backend import PlcBackend

logger = logging.getLogger(__name__)

# Lazy import to avoid circular dependency
def _get_event_logger_class():
    from cpsforge.plc.event_logger import PlcEventLogger
    return PlcEventLogger


class PLCConnectionError(RuntimeError):
    """Raised when the PLC cannot be reached or the connection is lost."""


class SafetyError(RuntimeError):
    """
    Raised when a write is attempted without live_writes_enabled.

    This is an intentional hard stop -- not an exception to be caught silently.
    """


# ---------------------------------------------------------------------------
# Value encoding / decoding helpers
# ---------------------------------------------------------------------------


def _encode_value(value: Any, word_len: S7WordLen) -> bytes:
    """Encode a Python value to the byte string expected by snap7."""
    if word_len == S7WordLen.REAL:
        return struct.pack(">f", float(value))
    elif word_len in (S7WordLen.DWORD, ):
        return struct.pack(">I", int(value) & 0xFFFFFFFF)
    elif word_len == S7WordLen.WORD:
        return struct.pack(">H", int(value) & 0xFFFF)
    elif word_len == S7WordLen.BYTE:
        return struct.pack("B", int(value) & 0xFF)
    elif word_len == S7WordLen.BIT:
        # snap7 read/write_area for BIT returns a single byte; bit is handled separately
        return struct.pack("B", 1 if value else 0)
    else:
        raise ValueError(f"Unsupported word_len for encoding: {word_len}")


def _decode_value(raw: bytes, word_len: S7WordLen, bit: int = 0) -> Any:
    """Decode a raw byte string returned by snap7 into a Python value."""
    if not raw:
        return None
    if word_len == S7WordLen.REAL:
        return struct.unpack(">f", raw[:4])[0]
    elif word_len == S7WordLen.DWORD:
        return struct.unpack(">I", raw[:4])[0]
    elif word_len == S7WordLen.WORD:
        return struct.unpack(">H", raw[:2])[0]
    elif word_len == S7WordLen.BYTE:
        return raw[0]
    elif word_len == S7WordLen.BIT:
        byte_val = raw[0]
        return bool((byte_val >> bit) & 0x01)
    else:
        raise ValueError(f"Unsupported word_len for decoding: {word_len}")


# ---------------------------------------------------------------------------
# PlcClient
# ---------------------------------------------------------------------------


class PlcClient(PlcBackend):
    """
    Thread-safe Siemens S7 PLC client built on python-snap7.

    Implements :class:`PlcBackend` for Siemens S7-1200/1500 PLCs via
    the python-snap7 (ISO-on-TCP) library.

    Parameters
    ----------
    config:
        :class:`PLCConfig` loaded from ``configs/system/plc.yaml``.

    Safety
    ------
    Writes are blocked unless ``config.live_writes_enabled`` is True.
    Do not set that flag unless you are intentionally writing to live hardware.
    """

    def __init__(self, config: PLCConfig, event_logger=None) -> None:
        self._config = config
        self._lock = Lock()
        self._client: Optional[Any] = None  # snap7.client.Client, imported lazily
        self._connected: bool = False
        self._event_logger = event_logger  # Optional[PlcEventLogger]
        self._current_step: int = 0        # Updated by runner each step

    # ------------------------------------------------------------------
    # Lazy snap7 import (allows the rest of CPSForge to import without snap7)
    # ------------------------------------------------------------------

    @staticmethod
    def _get_snap7():
        """Import snap7 at runtime so the package is optional at import time."""
        try:
            import snap7
            return snap7
        except ImportError as exc:
            raise ImportError(
                "python-snap7 is not installed. "
                "Install it with: pip install python-snap7\n"
                "You will also need the native snap7 shared library (snap7.dll / libsnap7.so)."
            ) from exc

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """
        Establish a connection to the PLC.

        Raises
        ------
        PLCConnectionError
            If the connection attempt fails after retries.
        """
        snap7 = self._get_snap7()
        with self._lock:
            if self._connected:
                return
            self._client = snap7.client.Client()
            last_exc: Optional[Exception] = None
            for attempt in range(1, self._config.reconnect_attempts + 2):
                try:
                    logger.info(
                        "Connecting to PLC at %s (rack=%d, slot=%d) -- attempt %d",
                        self._config.host,
                        self._config.rack,
                        self._config.slot,
                        attempt,
                    )
                    self._client.connect(
                        self._config.host,
                        self._config.rack,
                        self._config.slot,
                        self._config.port,
                    )
                    self._connected = True
                    logger.info("PLC connected: %s", self._config.host)
                    if self._event_logger:
                        self._event_logger.log_connect(self._config.host)
                    return
                except Exception as exc:
                    last_exc = exc
                    logger.warning("Connection attempt %d failed: %s", attempt, exc)
                    if attempt <= self._config.reconnect_attempts:
                        time.sleep(self._config.reconnect_delay_s)
            raise PLCConnectionError(
                f"Could not connect to PLC at {self._config.host} "
                f"after {self._config.reconnect_attempts + 1} attempts: {last_exc}"
            )

    def disconnect(self) -> None:
        """Cleanly disconnect from the PLC."""
        with self._lock:
            if self._client is not None and self._connected:
                try:
                    self._client.disconnect()
                    logger.info("PLC disconnected.")
                    if self._event_logger:
                        self._event_logger.log_disconnect()
                except Exception as exc:
                    logger.warning("Error during PLC disconnect: %s", exc)
            self._connected = False
            self._client = None

    def is_connected(self) -> bool:
        """Return True if the client believes it is connected."""
        with self._lock:
            if not self._connected or self._client is None:
                return False
            try:
                return bool(self._client.get_connected())
            except Exception:
                return False

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check. Returns True if PLC is reachable."""
        with self._lock:
            if not self._connected or self._client is None:
                return False
            try:
                # get_cpu_info() is unavailable on some S7-1200/1500 PLCs.
                # Fall back to get_connected() + get_cpu_state() which works
                # on all S7 models reachable via ISO-on-TCP.
                if not self._client.get_connected():
                    return False
                self._client.get_cpu_state()
                return True
            except Exception as exc:
                logger.debug("PLC health check failed: %s", exc)
                return False

    def _ensure_connected(self) -> None:
        """Reconnect if the connection was dropped."""
        if not self.is_connected():
            logger.info("PLC connection lost -- attempting reconnect.")
            self.connect()

    # ------------------------------------------------------------------
    # Scene selector -- infrastructure write (bypasses live_writes_enabled)
    # ------------------------------------------------------------------

    def switch_active_scene(self, scene_id: int) -> bool:
        """
        Write the active scene ID to DB_Config.ActiveScene (DB2, INT at byte 0).

        This is a PLC infrastructure write, not an attack write.  It is exempt
        from the ``live_writes_enabled`` safety gate because:
          - It must succeed for ANY scene to produce meaningful I/O data.
          - It is always an intentional, operator-driven action.
          - The scene selector does not actuate physical plant equipment; it only
            controls which FB logic block the OB1 scan cycle delegates to.

        Parameters
        ----------
        scene_id:
            Integer 1-21 matching the CASE selector values defined in OB_Main.scl.

        Returns
        -------
        bool
            True on success, False on PLC communication error.
        """
        self._ensure_connected()
        if not (1 <= scene_id <= 21):
            logger.error("switch_active_scene: scene_id %d out of range [1,21].", scene_id)
            return False
        raw = struct.pack(">h", scene_id)  # big-endian signed INT (S7 INT = 2 bytes)
        with self._lock:
            try:
                self._client.write_area(
                    self._to_snap7_area(S7Area.DB),
                    2,          # DB_Config = DB2 (TIA Portal-assigned number)
                    0,          # byte offset for ActiveScene
                    bytearray(raw),
                )
                logger.info(
                    "DB_Config.ActiveScene set to %d — OB_Main will now run scene %d FB.",
                    scene_id,
                    scene_id,
                )
                return True
            except Exception as exc:
                logger.error(
                    "Failed to write ActiveScene=%d to DB1,INT0: %s. "
                    "The PLC will continue running its previous scene.",
                    scene_id,
                    exc,
                )
                return False

    # ------------------------------------------------------------------
    # Tag I/O -- internal raw read/write
    # ------------------------------------------------------------------

    @staticmethod
    def _to_snap7_area(area: S7Area):
        """Convert internal S7Area enum to snap7.Area for snap7 v2+ compatibility."""
        import snap7
        return snap7.Area(area.value)

    def _raw_read(self, addr: S7Address) -> Optional[bytes]:
        """Read raw bytes from the PLC for one address."""
        with self._lock:
            try:
                data = self._client.read_area(
                    self._to_snap7_area(addr.area),
                    addr.db_number,
                    addr.start,
                    addr.size,
                )
                return bytes(data)
            except Exception as exc:
                logger.warning("PLC read error at %s: %s", addr, exc)
                return None

    def _raw_write(self, addr: S7Address, raw: bytes) -> bool:
        """Write raw bytes to the PLC for one address. Returns True on success."""
        if not self._config.live_writes_enabled:
            raise SafetyError(
                "Live writes are disabled (live_writes_enabled=False). "
                "Set live_writes_enabled=True in plc.yaml or CPSFORGE_LIVE_WRITES=true in .env "
                "to enable real PLC writes."
            )
        with self._lock:
            try:
                self._client.write_area(
                    self._to_snap7_area(addr.area),
                    addr.db_number,
                    addr.start,
                    bytearray(raw),
                )
                return True
            except Exception as exc:
                logger.error("PLC write error at %s: %s", addr, exc)
                return False

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def read_tag(self, tag: TagDefinition) -> Optional[Any]:
        """
        Read a single tag from the PLC.

        Returns the decoded Python value (float, int, bool) or None on error.
        """
        self._ensure_connected()
        addr = parse_address(tag.address)
        raw = self._raw_read(addr)
        if raw is None:
            return None
        return _decode_value(raw, addr.word_len, addr.bit)

    def read_many(self, tags: List[TagDefinition]) -> Dict[str, Optional[Any]]:
        """
        Read multiple tags in sequence.

        Returns a dict keyed by tag name. Missing/error reads return None.
        """
        self._ensure_connected()
        results: Dict[str, Optional[Any]] = {}
        for tag in tags:
            results[tag.name] = self.read_tag(tag)
        if self._event_logger:
            self._event_logger.log_poll(self._current_step, results)
        return results

    # ------------------------------------------------------------------
    # Public write API (shielded -- guard enforced here)
    # ------------------------------------------------------------------

    def write_tag(self, tag: TagDefinition, value: Any) -> bool:
        """
        Write a single tag to the PLC.

        This method is the only legitimate write path. It raises
        :class:`SafetyError` if ``live_writes_enabled`` is False.

        External callers (attackers, orchestrators) must route writes through
        :mod:`cpsforge.shield` which calls this method only after approval.

        Returns True on success.
        """
        self._ensure_connected()
        addr = parse_address(tag.address)
        raw = _encode_value(value, addr.word_len)
        success = self._raw_write(addr, raw)
        if success:
            logger.debug("PLC write: %s = %s", tag.name, value)
            if self._event_logger:
                self._event_logger.log_write(
                    step_id=self._current_step,
                    tag_name=tag.name,
                    address_str=tag.address,
                    written_value=value,
                    db_number=addr.db_number,
                    byte_offset=addr.start,
                    data_type=addr.word_len.name,
                )
        return success

    def write_many(self, tag_values: Dict[TagDefinition, Any]) -> Dict[str, bool]:
        """
        Write multiple tags sequentially.

        Returns a dict of tag_name -> bool indicating per-tag success.
        """
        results: Dict[str, bool] = {}
        for tag, value in tag_values.items():
            results[tag.name] = self.write_tag(tag, value)
        return results

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "PlcClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()
