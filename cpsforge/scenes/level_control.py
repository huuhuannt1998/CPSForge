"""
CPSForge Scene -- Level Control
================================
Continuous-process level control scene for Factory I/O with a Siemens S7 PLC.

Physical process summary:
  - Fill valve controls water inflow to the tank.
  - Discharge valve controls water outflow.
  - A level meter reads the current water level (0.0–10.0 range).
  - A flow meter reads the current flow rate.
  - Setpoint input determines the desired level.
  - PLC PID loop tracks the setpoint by adjusting the fill valve.
  - Start/Reset/Stop buttons and corresponding indicator lights.
  - Running flag and Enable flag control process execution.

Derived features computed per snapshot:
  - level_error       : setpoint - level
  - level_rate        : Δlevel / Δt (per second)
  - valve_balance     : fill_valve - discharge_valve
  - level_deviation   : absolute deviation from nominal midpoint (5.0)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from cpsforge.core.models import PlantSnapshot, SceneProfile
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)

# Nominal process operating range
_NOMINAL_SETPOINT = 5.0
_LEVEL_RANGE = 10.0


class LevelControlScene(BaseScene):
    """Level Control scene implementation."""

    def __init__(self, profile: SceneProfile) -> None:
        super().__init__(profile)
        self._prev_level: Optional[float] = None
        self._prev_ts_s: Optional[float] = None

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        """Compute level-control-specific derived features."""
        features: Dict[str, float] = {}

        level = self._get_tag_value(snapshot, "level_meter")
        setpoint = self._get_tag_value(snapshot, "setpoint_in")
        fill = self._get_tag_value(snapshot, "fill_valve")
        discharge = self._get_tag_value(snapshot, "discharge_valve")

        # Level error (setpoint tracking)
        if level is not None and setpoint is not None:
            features["level_error"] = float(setpoint) - float(level)

        # Level rate of change (per second)
        ts_s = snapshot.timestamp.timestamp()
        if level is not None and self._prev_level is not None and self._prev_ts_s is not None:
            dt = ts_s - self._prev_ts_s
            if dt > 0:
                features["level_rate"] = (float(level) - float(self._prev_level)) / dt
        self._prev_level = float(level) if level is not None else self._prev_level
        self._prev_ts_s = ts_s

        # Valve balance (fill minus discharge)
        if fill is not None and discharge is not None:
            features["valve_balance"] = float(fill) - float(discharge)

        # Absolute deviation from nominal midpoint
        if level is not None:
            features["level_deviation"] = abs(float(level) - _NOMINAL_SETPOINT)

        snapshot.derived_features.update(features)
        return features

    # ------------------------------------------------------------------
    # Process impact scoring
    # ------------------------------------------------------------------

    def compute_process_impact(
        self, before: PlantSnapshot, after: PlantSnapshot
    ) -> float:
        """
        Compute a scalar process-impact score in [0, inf).

        Combines:
          - Level deviation from nominal midpoint (normalised by range)
          - Change in level between before and after snapshots
          - Valve position anomalies (both fully open or both fully closed)
          - Enable flag toggled off
        """
        level_before = self._get_tag_value(before, "level_meter")
        level_after = self._get_tag_value(after, "level_meter")

        impact = 0.0

        # Level deviation from nominal midpoint
        if level_after is not None:
            dev = abs(float(level_after) - _NOMINAL_SETPOINT) / _LEVEL_RANGE
            impact += dev

        # Absolute change in level
        if level_before is not None and level_after is not None:
            delta = abs(float(level_after) - float(level_before)) / _LEVEL_RANGE
            impact += delta

        # Valve anomaly: both fully open
        fill = self._get_tag_value(after, "fill_valve")
        discharge = self._get_tag_value(after, "discharge_valve")
        if fill is not None and discharge is not None:
            if float(fill) > 9.0 and float(discharge) > 9.0:
                impact += 0.5
            elif float(fill) < 0.5 and float(discharge) < 0.5:
                impact += 0.3

        # Enable toggled off
        enable_before = self._get_tag_value(before, "enable")
        enable_after = self._get_tag_value(after, "enable")
        if enable_before and not enable_after:
            impact += 0.5

        # Level exceeding safety boundary
        if level_after is not None:
            lval = float(level_after)
            if lval > 9.5 or lval < 0.5:
                impact += 0.5

        return round(impact, 4)
