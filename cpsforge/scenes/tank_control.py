"""
CPSForge Scene -- Tank Level Control
=====================================
Reference implementation of the :class:`BaseScene` for the single-tank
level control process deployed in Factory I/O with a Siemens S7 PLC.

Physical process summary:
  - Pump P1 fills the tank at variable speed.
  - Drain valve V1 controls outflow.
  - LT1 measures tank fill level (0-100 %).
  - PID controller tracks level_setpoint.
  - High-level (>90%) and low-level (<10%) alarms protect boundaries.

Derived features computed per snapshot:
  - level_error       : setpoint - level
  - level_rate        : Deltalevel / Deltat  (approximated as (level_t - level_{t-1}) / dt)
  - flow_balance      : inlet_flow - outlet_flow
  - pid_tracking_err  : pid_output - pump_speed (should be ~0 in auto mode)
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, Optional

from cpsforge.core.models import PlantSnapshot, SceneProfile
from cpsforge.scenes.base import BaseScene

logger = logging.getLogger(__name__)

# Nominal process operating range (used for impact scoring)
_NOMINAL_LEVEL_MIN = 30.0
_NOMINAL_LEVEL_MAX = 70.0
_NOMINAL_SETPOINT = 50.0


class TankControlScene(BaseScene):
    """
    Tank Level Control scene implementation.

    This is the primary reference scene for CPSForge Phase 1 experiments.
    """

    def __init__(self, profile: SceneProfile) -> None:
        super().__init__(profile)
        self._prev_level: Optional[float] = None
        self._prev_ts_s: Optional[float] = None

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_derived_features(self, snapshot: PlantSnapshot) -> Dict[str, float]:
        """
        Compute tank-specific derived features and inject them into the snapshot.

        Features are also returned for convenience.
        """
        level: Optional[float] = snapshot.sensors.get("tank_level")
        setpoint: Optional[float] = snapshot.setpoints.get("level_setpoint")
        inlet: Optional[float] = snapshot.sensors.get("inlet_flow")
        outlet: Optional[float] = snapshot.sensors.get("outlet_flow")
        pid_out: Optional[float] = snapshot.controller_state.get("pid_output")
        pump: Optional[float] = snapshot.actuators.get("pump_speed")

        features: Dict[str, float] = {}

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

        # Flow balance (inlet - outlet)
        if inlet is not None and outlet is not None:
            features["flow_balance"] = float(inlet) - float(outlet)

        # PID tracking error (should be ~0 when in auto mode)
        if pid_out is not None and pump is not None:
            features["pid_tracking_err"] = float(pid_out) - float(pump)

        # Absolute deviation from nominal mid-point
        if level is not None:
            features["level_deviation"] = abs(float(level) - _NOMINAL_SETPOINT)

        # Update snapshot in-place
        snapshot.derived_features.update(features)
        return features

    # ------------------------------------------------------------------
    # Process impact scoring
    # ------------------------------------------------------------------

    def compute_process_impact(
        self, before: PlantSnapshot, after: PlantSnapshot
    ) -> float:
        """
        Return a scalar process-impact score in [0, inf).

        Combines:
          - Absolute level deviation from nominal (0-100 % normalised by range)
          - Change in level between before and after snapshots
          - Alarm activation (binary, weighted)
        """
        level_before = self._get_tag_value(before, "tank_level")
        level_after = self._get_tag_value(after, "tank_level")

        impact = 0.0

        # Level deviation from nominal midpoint
        if level_after is not None:
            dev = abs(float(level_after) - _NOMINAL_SETPOINT) / 50.0  # normalise to 0-1
            impact += dev

        # Absolute change in level
        if level_before is not None and level_after is not None:
            delta = abs(float(level_after) - float(level_before)) / 100.0
            impact += delta

        # Alarm activation penalty
        for alarm_tag in ("high_level_alarm", "low_level_alarm", "pump_fault"):
            val = after.alarms.get(alarm_tag)
            if val:
                impact += 0.5

        return round(impact, 4)
