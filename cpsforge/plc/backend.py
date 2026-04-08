"""
cpsforge.plc.backend
=====================
Abstract base class for PLC communication backends.

CPSForge supports multiple PLC backends:

  - **Snap7Backend** (default): Siemens S7 via python-snap7.
  - **ModbusBackend**: Modbus TCP for OpenPLC and other soft PLCs.

All backends expose the same public interface so the runner, observer,
shield, and defense chain work identically regardless of which PLC is
attached.
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional

from cpsforge.core.models import TagDefinition


class PlcBackend(abc.ABC):
    """
    Abstract base class that every PLC communication backend must implement.

    The runner and observer interact with the PLC exclusively through this
    interface.  Backend-specific details (S7 data blocks, Modbus registers,
    connection parameters) are hidden behind these methods.
    """

    # Step counter — the runner updates this each polling cycle so the
    # event logger can annotate events with the current experiment step.
    _current_step: int = 0

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def connect(self) -> None:
        """Establish a connection to the PLC. Raise on failure."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Cleanly disconnect from the PLC."""

    @abc.abstractmethod
    def is_connected(self) -> bool:
        """Return True if the backend believes it is connected."""

    def health_check(self) -> bool:
        """Lightweight connectivity check. Default delegates to is_connected()."""
        return self.is_connected()

    # ------------------------------------------------------------------
    # Tag I/O
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def read_tag(self, tag: TagDefinition) -> Optional[Any]:
        """Read a single tag value. Returns None on error."""

    @abc.abstractmethod
    def read_many(self, tags: List[TagDefinition]) -> Dict[str, Optional[Any]]:
        """Read multiple tags. Returns dict keyed by tag name; None on error."""

    @abc.abstractmethod
    def write_tag(self, tag: TagDefinition, value: Any) -> bool:
        """Write a single tag value. Returns True on success."""

    def write_many(self, tag_values: Dict[TagDefinition, Any]) -> Dict[str, bool]:
        """Write multiple tags sequentially. Returns per-tag success dict."""
        results: Dict[str, bool] = {}
        for tag, value in tag_values.items():
            results[tag.name] = self.write_tag(tag, value)
        return results

    # ------------------------------------------------------------------
    # Optional scene management (S7-specific, no-op by default)
    # ------------------------------------------------------------------

    def switch_active_scene(self, scene_id: int) -> bool:
        """Switch the active Factory I/O scene. Only meaningful for S7 backends."""
        return False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "PlcBackend":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()
