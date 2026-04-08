"""
cpsforge.plc.event_logger
=========================
Structured logger for all S7 PLC I/O events observed during an experiment run.

Records every read (poll), every executed write (attack), and every blocked
write (shield/defense decision) with precise timestamps and context labels.
The output JSONL file can be used directly as paper evidence:

  - Normal traffic: periodic poll_read events every ~500 ms
  - Attack traffic: attack_write events interspersed, showing tag manipulation
  - Defense effect:  blocked_write events that never become attack_writes

Output: data/captures/<run_id>_plc_events.jsonl
Schema: PlcEvent (see dataclass below)
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

EVENT_POLL_READ      = "poll_read"        # Periodic tag poll (read_many)
EVENT_ATTACK_WRITE   = "attack_write"     # Approved write executed on PLC
EVENT_BLOCKED_WRITE  = "blocked_write"    # Write blocked before reaching PLC
EVENT_CONNECT        = "connect"          # PLC TCP connection established
EVENT_DISCONNECT     = "disconnect"       # PLC TCP connection closed


@dataclass
class PlcEvent:
    """One structured event record in the PLC I/O log."""

    # Timing
    timestamp_iso: str           # ISO-8601 UTC
    timestamp_ns: int            # monotonic nanoseconds (relative to run start)
    elapsed_s: float             # seconds since run start

    # Provenance
    run_id: str
    step_id: Optional[int]       # experiment step counter (None for connect/disconnect)
    event_type: str              # EVENT_* constant

    # S7 address details (populated for read/write events)
    tag_name: Optional[str] = None
    db_number: Optional[int] = None
    byte_offset: Optional[int] = None
    data_type: Optional[str] = None   # "REAL", "BOOL", "INT", "DINT"
    address_str: Optional[str] = None # raw address e.g. "DB14,REAL24"

    # Values
    written_value: Optional[Any] = None   # for write events
    read_values: Optional[Dict[str, Any]] = None  # for poll_read (all tags)

    # Defense context (for blocked_write)
    block_reason: Optional[str] = None    # "range_violation", "phase_inconsistent", etc.
    block_stage: Optional[str] = None     # "safety_shield", "phase_shield", "intent_checker", "llm_defender"
    suspicion_score: Optional[float] = None

    # Attack context (for attack_write)
    attack_action_type: Optional[str] = None   # "actuator_override", "setpoint_shift", etc.
    expected_effect: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


# ---------------------------------------------------------------------------
# PlcEventLogger
# ---------------------------------------------------------------------------


class PlcEventLogger:
    """
    Writes PlcEvent records to a JSONL file for one experiment run.

    Usage
    -----
    logger = PlcEventLogger(run_id="20260330T...", output_dir="data/captures")
    logger.open()

    # In PlcClient.read_many():
    logger.log_poll(step_id=5, tag_values={"level_meter": 5.2, ...})

    # In runner after approved write:
    logger.log_write(step_id=7, tag_name="fill_valve", address_str="DB14,REAL24",
                     written_value=9.5, action_type="actuator_override")

    # In runner after blocked write:
    logger.log_blocked(step_id=9, tag_name="fill_valve", written_value=11.0,
                       block_stage="safety_shield", block_reason="range_violation")

    logger.close()
    """

    def __init__(self, run_id: str, output_dir: str = "data/captures") -> None:
        self._run_id = run_id
        self._output_dir = Path(output_dir)
        self._fh = None
        self._run_start_ns: int = time.monotonic_ns()
        self._path: Optional[Path] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._path = self._output_dir / f"{self._run_id}_plc_events.jsonl"
        self._fh = open(self._path, "w", encoding="utf-8")
        self._run_start_ns = time.monotonic_ns()
        logger.debug("PlcEventLogger opened: %s", self._path)

    def close(self) -> None:
        if self._fh:
            self._fh.flush()
            self._fh.close()
            self._fh = None
            logger.debug("PlcEventLogger closed: %s", self._path)

    @property
    def path(self) -> Optional[Path]:
        return self._path

    # ------------------------------------------------------------------
    # Event builders
    # ------------------------------------------------------------------

    def _base(self, event_type: str, step_id: Optional[int]) -> PlcEvent:
        now_ns = time.monotonic_ns()
        elapsed = (now_ns - self._run_start_ns) / 1e9
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        return PlcEvent(
            timestamp_iso=ts,
            timestamp_ns=now_ns,
            elapsed_s=round(elapsed, 4),
            run_id=self._run_id,
            step_id=step_id,
            event_type=event_type,
        )

    def log_connect(self, host: str) -> None:
        if not self._fh:
            return
        ev = self._base(EVENT_CONNECT, step_id=None)
        ev.tag_name = host
        self._write(ev)

    def log_disconnect(self) -> None:
        if not self._fh:
            return
        ev = self._base(EVENT_DISCONNECT, step_id=None)
        self._write(ev)

    def log_poll(self, step_id: int, tag_values: Dict[str, Any]) -> None:
        """Log a full tag poll (read_many result)."""
        if not self._fh:
            return
        ev = self._base(EVENT_POLL_READ, step_id=step_id)
        ev.read_values = {k: (float(v) if isinstance(v, float) else v)
                         for k, v in tag_values.items() if v is not None}
        self._write(ev)

    def log_write(
        self,
        step_id: int,
        tag_name: str,
        address_str: str,
        written_value: Any,
        action_type: Optional[str] = None,
        expected_effect: Optional[str] = None,
        db_number: Optional[int] = None,
        byte_offset: Optional[int] = None,
        data_type: Optional[str] = None,
    ) -> None:
        """Log an approved, executed write to the PLC."""
        if not self._fh:
            return
        ev = self._base(EVENT_ATTACK_WRITE, step_id=step_id)
        ev.tag_name = tag_name
        ev.address_str = address_str
        ev.db_number = db_number
        ev.byte_offset = byte_offset
        ev.data_type = data_type
        ev.written_value = float(written_value) if isinstance(written_value, float) else written_value
        ev.attack_action_type = action_type
        ev.expected_effect = expected_effect
        self._write(ev)

    def log_blocked(
        self,
        step_id: int,
        tag_name: str,
        written_value: Any,
        block_stage: str,
        block_reason: str,
        suspicion_score: Optional[float] = None,
        address_str: Optional[str] = None,
    ) -> None:
        """Log a write that was blocked by the defense chain before reaching the PLC."""
        if not self._fh:
            return
        ev = self._base(EVENT_BLOCKED_WRITE, step_id=step_id)
        ev.tag_name = tag_name
        ev.address_str = address_str
        ev.written_value = float(written_value) if isinstance(written_value, float) else written_value
        ev.block_stage = block_stage
        ev.block_reason = block_reason
        ev.suspicion_score = suspicion_score
        self._write(ev)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(self, event: PlcEvent) -> None:
        try:
            self._fh.write(event.to_json() + "\n")
        except Exception as exc:
            logger.warning("PlcEventLogger write error: %s", exc)

    def __enter__(self) -> "PlcEventLogger":
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()
